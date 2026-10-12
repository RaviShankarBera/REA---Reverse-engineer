#include "authority.hpp"

#include <cmath>
#include <cstring>
#include <limits>
#include <objbase.h>
#include <objidl.h>
#include <wincodec.h>

namespace rea {

namespace {

constexpr DWORD CAPTURE_TIMEOUT_MS = 5000;
constexpr uint64_t MAX_SOURCE_PIXELS = 4ULL * 1024ULL * 1024ULL;
constexpr size_t MAX_PNG_BYTES = 3ULL * 1024ULL * 1024ULL;

class ComApartment {
 public:
  ComApartment() {
    const auto result = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (result == S_OK || result == S_FALSE) owns_ = true;
    else if (result != RPC_E_CHANGED_MODE)
      throw Failure("Initialize Windows image encoder failed", L"", static_cast<DWORD>(result));
  }
  ~ComApartment() {
    if (owns_) CoUninitialize();
  }

 private:
  bool owns_ = false;
};

template <typename T>
class ComPointer {
 public:
  ComPointer() = default;
  ~ComPointer() { reset(); }
  ComPointer(const ComPointer&) = delete;
  ComPointer& operator=(const ComPointer&) = delete;
  T* get() const { return value_; }
  T** out() {
    reset();
    return &value_;
  }
  void reset(T* next = nullptr) {
    if (value_ != nullptr) value_->Release();
    value_ = next;
  }

 private:
  T* value_ = nullptr;
};

/** Fixed-capacity IStream prevents a WIC encoder from growing an unbounded HGLOBAL. */
class FixedMemoryStream final : public IStream {
 public:
  explicit FixedMemoryStream(std::vector<BYTE>& buffer) : buffer_(buffer) {}

  STDMETHODIMP QueryInterface(REFIID iid, void** result) override {
    if (result == nullptr) return E_POINTER;
    *result = nullptr;
    if (IsEqualIID(iid, IID_IUnknown) || IsEqualIID(iid, IID_ISequentialStream) ||
        IsEqualIID(iid, IID_IStream)) {
      *result = static_cast<IStream*>(this);
      AddRef();
      return S_OK;
    }
    return E_NOINTERFACE;
  }

  STDMETHODIMP_(ULONG) AddRef() override { return references_.fetch_add(1) + 1; }

  STDMETHODIMP_(ULONG) Release() override {
    const ULONG remaining = references_.fetch_sub(1) - 1;
    if (remaining == 0) delete this;
    return remaining;
  }

  STDMETHODIMP Read(void* target, ULONG requested, ULONG* observed) override {
    if (observed != nullptr) *observed = 0;
    if (target == nullptr && requested != 0) return STG_E_INVALIDPOINTER;
    const size_t available = position_ >= size_ ? 0 : size_ - position_;
    const size_t count = std::min(available, static_cast<size_t>(requested));
    if (count != 0) std::memcpy(target, buffer_.data() + position_, count);
    position_ += count;
    if (observed != nullptr) *observed = static_cast<ULONG>(count);
    return count == requested ? S_OK : S_FALSE;
  }

  STDMETHODIMP Write(const void* source, ULONG requested, ULONG* observed) override {
    if (observed != nullptr) *observed = 0;
    if (source == nullptr && requested != 0) return STG_E_INVALIDPOINTER;
    const size_t count = static_cast<size_t>(requested);
    if (position_ > buffer_.size() || count > buffer_.size() - position_)
      return STG_E_MEDIUMFULL;
    if (count != 0) std::memcpy(buffer_.data() + position_, source, count);
    position_ += count;
    size_ = std::max(size_, position_);
    if (observed != nullptr) *observed = requested;
    return S_OK;
  }

  STDMETHODIMP Seek(LARGE_INTEGER move, DWORD origin, ULARGE_INTEGER* observed) override {
    const LONGLONG base = origin == STREAM_SEEK_SET ? 0
                        : origin == STREAM_SEEK_CUR ? static_cast<LONGLONG>(position_)
                        : origin == STREAM_SEEK_END ? static_cast<LONGLONG>(size_)
                        : -1;
    if (base < 0) return STG_E_INVALIDFUNCTION;
    const LONGLONG delta = move.QuadPart;
    if ((delta > 0 && base > std::numeric_limits<LONGLONG>::max() - delta) ||
        (delta < 0 && base < std::numeric_limits<LONGLONG>::min() - delta))
      return STG_E_INVALIDFUNCTION;
    const LONGLONG next = base + delta;
    if (next < 0 || static_cast<ULONGLONG>(next) > buffer_.size())
      return STG_E_MEDIUMFULL;
    position_ = static_cast<size_t>(next);
    if (observed != nullptr) observed->QuadPart = position_;
    return S_OK;
  }

  STDMETHODIMP SetSize(ULARGE_INTEGER requested) override {
    if (requested.QuadPart > buffer_.size()) return STG_E_MEDIUMFULL;
    size_ = static_cast<size_t>(requested.QuadPart);
    position_ = std::min(position_, size_);
    return S_OK;
  }

  STDMETHODIMP CopyTo(IStream* destination, ULARGE_INTEGER requested,
                      ULARGE_INTEGER* read, ULARGE_INTEGER* written) override {
    if (read != nullptr) read->QuadPart = 0;
    if (written != nullptr) written->QuadPart = 0;
    if (destination == nullptr) return STG_E_INVALIDPOINTER;
    const size_t count = std::min(
        position_ >= size_ ? 0 : size_ - position_,
        requested.QuadPart > std::numeric_limits<size_t>::max()
            ? buffer_.size()
            : static_cast<size_t>(requested.QuadPart));
    ULONG copied = 0;
    const HRESULT result = destination->Write(buffer_.data() + position_, static_cast<ULONG>(count), &copied);
    position_ += copied;
    if (read != nullptr) read->QuadPart = copied;
    if (written != nullptr) written->QuadPart = copied;
    return result;
  }

  STDMETHODIMP Commit(DWORD) override { return S_OK; }
  STDMETHODIMP Revert() override { return E_NOTIMPL; }
  STDMETHODIMP LockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) override { return STG_E_INVALIDFUNCTION; }
  STDMETHODIMP UnlockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) override { return STG_E_INVALIDFUNCTION; }

  STDMETHODIMP Stat(STATSTG* observed, DWORD) override {
    if (observed == nullptr) return STG_E_INVALIDPOINTER;
    std::memset(observed, 0, sizeof(*observed));
    observed->type = STGTY_STREAM;
    observed->cbSize.QuadPart = size_;
    observed->grfMode = STGM_READWRITE;
    return S_OK;
  }

  STDMETHODIMP Clone(IStream**) override { return E_NOTIMPL; }

  size_t size() const { return size_; }

 private:
  std::atomic<ULONG> references_{1};
  std::vector<BYTE>& buffer_;
  size_t position_ = 0;
  size_t size_ = 0;
};

class DeviceContext {
 public:
  DeviceContext() : value_(CreateCompatibleDC(nullptr)) {
    require(value_ != nullptr, "Create selected-window capture surface failed");
  }
  ~DeviceContext() {
    if (value_ != nullptr) DeleteDC(value_);
  }
  DeviceContext(const DeviceContext&) = delete;
  DeviceContext& operator=(const DeviceContext&) = delete;
  HDC get() const { return value_; }

 private:
  HDC value_ = nullptr;
};

class Bitmap {
 public:
  Bitmap(int width, int height) {
    const uint64_t byteCount = static_cast<uint64_t>(width) * static_cast<uint64_t>(height) * 4ULL;
    require(byteCount <= std::numeric_limits<size_t>::max(), "Selected-window bitmap exceeds memory limits", L"",
            ERROR_NOT_ENOUGH_MEMORY);
    bytes_ = static_cast<size_t>(byteCount);
    BITMAPINFO description{};
    description.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    description.bmiHeader.biWidth = width;
    description.bmiHeader.biHeight = -height;
    description.bmiHeader.biPlanes = 1;
    description.bmiHeader.biBitCount = 32;
    description.bmiHeader.biCompression = BI_RGB;
    value_ = CreateDIBSection(nullptr, &description, DIB_RGB_COLORS, &pixels_, nullptr, 0);
    require(value_ != nullptr && pixels_ != nullptr, "Create selected-window bitmap failed");
    std::memset(pixels_, 0, bytes_);
  }
  ~Bitmap() {
    if (value_ != nullptr) DeleteObject(value_);
  }
  Bitmap(const Bitmap&) = delete;
  Bitmap& operator=(const Bitmap&) = delete;
  HBITMAP get() const { return value_; }
  void* pixels() const { return pixels_; }
  void setOpaqueAlpha() const {
    auto* bytes = static_cast<BYTE*>(pixels_);
    for (size_t index = 3; index < bytes_; index += 4) bytes[index] = 0xff;
  }

 private:
  HBITMAP value_ = nullptr;
  void* pixels_ = nullptr;
  size_t bytes_ = 0;
};

class SelectedObject {
 public:
  SelectedObject(HDC dc, HGDIOBJ object) : dc_(dc), previous_(SelectObject(dc, object)) {
    require(previous_ != nullptr && previous_ != HGDI_ERROR, "Select selected-window bitmap failed");
  }
  ~SelectedObject() {
    if (previous_ != nullptr && previous_ != HGDI_ERROR) SelectObject(dc_, previous_);
  }
  SelectedObject(const SelectedObject&) = delete;
  SelectedObject& operator=(const SelectedObject&) = delete;

 private:
  HDC dc_;
  HGDIOBJ previous_;
};

void checkHr(HRESULT result, const char* constraint) {
  require(SUCCEEDED(result), constraint, L"", static_cast<DWORD>(result));
}

DWORD positiveDword(napi_env env, napi_value value, const char* constraint) {
  const auto candidate = numeric(env, value);
  require(std::isfinite(candidate) && std::floor(candidate) == candidate && candidate >= 1 &&
              candidate <= static_cast<double>(std::numeric_limits<DWORD>::max()),
          constraint, L"", ERROR_INVALID_PARAMETER);
  return static_cast<DWORD>(candidate);
}

int positiveDimension(napi_env env, napi_value value) {
  const auto candidate = numeric(env, value);
  require(std::isfinite(candidate) && std::floor(candidate) == candidate && candidate >= 1 &&
              candidate <= 4096,
          "Selected-window dimension limit is invalid", L"", ERROR_INVALID_PARAMETER);
  return static_cast<int>(candidate);
}

ULONG_PTR parseWindowHandle(const std::wstring& text) {
  require(text.size() > 2 && text[0] == L'0' && text[1] == L'x',
          "Window handle must be canonical lowercase hexadecimal", text, ERROR_INVALID_PARAMETER);
  require(text.size() == 3 || text[2] != L'0',
          "Window handle must not contain leading zeroes", text, ERROR_INVALID_PARAMETER);
  ULONG_PTR result = 0;
  for (size_t index = 2; index < text.size(); ++index) {
    const wchar_t character = text[index];
    const ULONG_PTR nibble = character >= L'0' && character <= L'9'
                                 ? static_cast<ULONG_PTR>(character - L'0')
                                 : character >= L'a' && character <= L'f'
                                     ? static_cast<ULONG_PTR>(character - L'a' + 10)
                                     : std::numeric_limits<ULONG_PTR>::max();
    require(nibble != std::numeric_limits<ULONG_PTR>::max(),
            "Window handle must be canonical lowercase hexadecimal", text, ERROR_INVALID_PARAMETER);
    require(result <= (std::numeric_limits<ULONG_PTR>::max() - nibble) / 16,
            "Window handle exceeds the native pointer range", text, ERROR_INVALID_PARAMETER);
    result = result * 16 + nibble;
  }
  require(result != 0, "Window handle must not be zero", text, ERROR_INVALID_PARAMETER);
  return result;
}

std::wstring hexHandle(ULONG_PTR value) {
  const wchar_t digits[] = L"0123456789abcdef";
  std::wstring rendered;
  do {
    rendered.push_back(digits[value & 0xf]);
    value >>= 4;
  } while (value != 0);
  std::reverse(rendered.begin(), rendered.end());
  return L"0x" + rendered;
}

Handle openProcessForCapture(DWORD pid) {
  Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
  require(process.valid(), "Open selected process for window identity failed", L"", GetLastError());
  return process;
}

std::wstring processImagePath(HANDLE process) {
  std::vector<wchar_t> buffer(32768);
  DWORD size = static_cast<DWORD>(buffer.size());
  require(QueryFullProcessImageNameW(process, 0, buffer.data(), &size) != FALSE,
          "Read selected process executable path failed");
  require(size > 0 && size < buffer.size(), "Selected process executable path is invalid", L"",
          ERROR_INVALID_DATA);
  return std::wstring(buffer.data(), size);
}

double processStartTimeMs(HANDLE process) {
  FILETIME created{}, exited{}, kernel{}, user{};
  require(GetProcessTimes(process, &created, &exited, &kernel, &user) != FALSE,
          "Read selected process start time failed");
  ULARGE_INTEGER value{};
  value.LowPart = created.dwLowDateTime;
  value.HighPart = created.dwHighDateTime;
  constexpr uint64_t WINDOWS_TO_UNIX_EPOCH_100NS = 116444736000000000ULL;
  require(value.QuadPart >= WINDOWS_TO_UNIX_EPOCH_100NS,
          "Selected process start time precedes the Unix epoch", L"", ERROR_INVALID_DATA);
  return static_cast<double>((value.QuadPart - WINDOWS_TO_UNIX_EPOCH_100NS) / 10000ULL);
}

std::wstring windowTitle(HWND window) {
  const int length = GetWindowTextLengthW(window);
  require(length >= 0 && length <= 32767, "Selected window title length is invalid", L"", ERROR_INVALID_DATA);
  std::vector<wchar_t> buffer(static_cast<size_t>(length) + 1);
  const int copied = GetWindowTextW(window, buffer.data(), static_cast<int>(buffer.size()));
  require(copied >= 0 && copied <= length, "Read selected window title failed");
  return std::wstring(buffer.data(), static_cast<size_t>(copied));
}

void validateWindowOwner(HWND window, DWORD expectedPid) {
  require(IsWindow(window) != FALSE, "Selected window no longer exists", L"", ERROR_INVALID_WINDOW_HANDLE);
  const DWORD observedPid = GetWindowThreadProcessId(window, nullptr);
  require(observedPid == expectedPid, "Selected window belongs to a different process", L"",
          ERROR_ACCESS_DENIED);
}

napi_value pngFromDib(napi_env env, int sourceWidth, int sourceHeight, void* pixels,
                      int maximumDimension) {
  const uint64_t sourceBytes = static_cast<uint64_t>(sourceWidth) * static_cast<uint64_t>(sourceHeight) * 4ULL;
  require(sourceBytes <= static_cast<uint64_t>(std::numeric_limits<UINT>::max()),
          "Selected-window bitmap exceeds encoder limits", L"", ERROR_NOT_ENOUGH_MEMORY);

  ComApartment apartment;
  ComPointer<IWICImagingFactory> factory;
  checkHr(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                            IID_IWICImagingFactory, reinterpret_cast<void**>(factory.out())),
          "Create Windows image encoder failed");
  ComPointer<IWICBitmap> bitmap;
  checkHr(factory.get()->CreateBitmapFromMemory(
              static_cast<UINT>(sourceWidth), static_cast<UINT>(sourceHeight), GUID_WICPixelFormat32bppBGRA,
              static_cast<UINT>(sourceWidth * 4), static_cast<UINT>(sourceBytes),
              static_cast<BYTE*>(pixels), bitmap.out()),
          "Create selected-window image failed");

  const int longest = std::max(sourceWidth, sourceHeight);
  const double scale = longest <= maximumDimension ? 1.0 : static_cast<double>(maximumDimension) / longest;
  const int width = std::max(1, static_cast<int>(std::floor(sourceWidth * scale)));
  const int height = std::max(1, static_cast<int>(std::floor(sourceHeight * scale)));
  IWICBitmapSource* source = bitmap.get();
  ComPointer<IWICBitmapScaler> scaler;
  if (width != sourceWidth || height != sourceHeight) {
    checkHr(factory.get()->CreateBitmapScaler(scaler.out()), "Create selected-window image scaler failed");
    checkHr(scaler.get()->Initialize(source, static_cast<UINT>(width), static_cast<UINT>(height),
                                     WICBitmapInterpolationModeFant),
            "Scale selected-window image failed");
    source = scaler.get();
  }

  std::vector<BYTE> encoded(MAX_PNG_BYTES);
  auto* fixedStream = new FixedMemoryStream(encoded);
  ComPointer<IStream> stream;
  stream.reset(fixedStream);
  ComPointer<IWICBitmapEncoder> encoder;
  checkHr(factory.get()->CreateEncoder(GUID_ContainerFormatPng, nullptr, encoder.out()),
          "Create selected-window PNG encoder failed");
  checkHr(encoder.get()->Initialize(stream.get(), WICBitmapEncoderNoCache),
          "Initialize selected-window PNG encoder failed");
  ComPointer<IWICBitmapFrameEncode> frame;
  ComPointer<IPropertyBag2> options;
  checkHr(encoder.get()->CreateNewFrame(frame.out(), options.out()), "Create selected-window PNG frame failed");
  checkHr(frame.get()->Initialize(options.get()), "Initialize selected-window PNG frame failed");
  checkHr(frame.get()->SetSize(static_cast<UINT>(width), static_cast<UINT>(height)),
          "Set selected-window PNG dimensions failed");
  WICPixelFormatGUID format = GUID_WICPixelFormat32bppBGRA;
  checkHr(frame.get()->SetPixelFormat(&format), "Set selected-window PNG format failed");
  checkHr(frame.get()->WriteSource(source, nullptr), "Write selected-window PNG pixels failed");
  checkHr(frame.get()->Commit(), "Commit selected-window PNG frame failed");
  checkHr(encoder.get()->Commit(), "Commit selected-window PNG failed");

  const size_t byteCount = fixedStream->size();
  require(byteCount > 0 && byteCount <= MAX_PNG_BYTES,
          "Selected-window PNG exceeds the retained byte limit", L"", ERROR_NOT_ENOUGH_MEMORY);
  napi_value result;
  const auto status = napi_create_buffer_copy(env, byteCount, encoded.data(), nullptr, &result);
  check(status);
  return result;
}

}  // namespace

napi_value windowCaptureCall(napi_env env, const std::vector<napi_value>& args) {
  require(args.size() == 3, "Selected-window capture requires pid, handle and maximum dimension", L"",
          ERROR_INVALID_PARAMETER);
  const DWORD pid = positiveDword(env, args[0], "Selected process ID is invalid");
  const std::wstring requestedHandle = wide(env, args[1]);
  const ULONG_PTR handle = parseWindowHandle(requestedHandle);
  const int maximumDimension = positiveDimension(env, args[2]);
  const HWND window = reinterpret_cast<HWND>(handle);

  validateWindowOwner(window, pid);
  auto process = openProcessForCapture(pid);
  const std::wstring imagePath = processImagePath(process.get());
  const double startTimeMs = processStartTimeMs(process.get());
  const std::wstring title = windowTitle(window);
  RECT bounds{};
  require(GetClientRect(window, &bounds) != FALSE, "Read selected window client bounds failed");
  const int width = bounds.right - bounds.left;
  const int height = bounds.bottom - bounds.top;
  require(width > 0 && height > 0 && static_cast<uint64_t>(width) * static_cast<uint64_t>(height) <= MAX_SOURCE_PIXELS,
          "Selected window client area exceeds the capture limit", L"", ERROR_NOT_ENOUGH_MEMORY);

  DeviceContext dc;
  Bitmap bitmap(width, height);
  SelectedObject selected(dc.get(), bitmap.get());
  DWORD_PTR ignored = 0;
  const UINT flags = PRF_CLIENT | PRF_ERASEBKGND;
  const LRESULT delivered = SendMessageTimeoutW(window, WM_PRINT,
                                                 reinterpret_cast<WPARAM>(dc.get()), flags,
                                                 SMTO_ABORTIFHUNG | SMTO_BLOCK, CAPTURE_TIMEOUT_MS, &ignored);
  require(delivered != 0, "Selected window did not render within the capture deadline", L"",
          GetLastError() == ERROR_SUCCESS ? ERROR_TIMEOUT : GetLastError());
  require(GdiFlush() != FALSE, "Flush selected-window drawing commands failed");
  bitmap.setOpaqueAlpha();
  validateWindowOwner(window, pid);
  auto observedProcess = openProcessForCapture(pid);
  require(processStartTimeMs(observedProcess.get()) == startTimeMs,
          "Selected process identity changed during capture", L"", ERROR_INVALID_HANDLE);
  require(processImagePath(observedProcess.get()) == imagePath,
          "Selected process executable changed during capture", L"", ERROR_INVALID_HANDLE);
  const int longest = std::max(width, height);
  const double scale = longest <= maximumDimension ? 1.0 : static_cast<double>(maximumDimension) / longest;
  const int renderedWidth = std::max(1, static_cast<int>(std::floor(width * scale)));
  const int renderedHeight = std::max(1, static_cast<int>(std::floor(height * scale)));

  auto result = object(env);
  set(env, result, "pid", number(env, static_cast<double>(pid)));
  set(env, result, "window_handle", string(env, hexHandle(handle)));
  set(env, result, "process_image_path", string(env, imagePath));
  set(env, result, "process_start_time_unix_ms", number(env, startTimeMs));
  set(env, result, "title", string(env, title));
  set(env, result, "source_width", number(env, width));
  set(env, result, "source_height", number(env, height));
  set(env, result, "width", number(env, renderedWidth));
  set(env, result, "height", number(env, renderedHeight));
  set(env, result, "png", pngFromDib(env, width, height, bitmap.pixels(), maximumDimension));
  return result;
}

}  // namespace rea
