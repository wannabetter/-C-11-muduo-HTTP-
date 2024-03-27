//
// Created by DELL on 2024/1/17.
//

#ifndef REACTOR_HTTP_H
#define REACTOR_HTTP_H

#include <regex>
#include <fstream>

#include <sys/stat.h>

#include "../Server.h"

#define DEFAULT_TIMEOUT  30

std::unordered_map<std::string, std::string> _mime_msg = {
        {".aac",    "audio/aac"},
        {".abw",    "application/x-abiword"},
        {".arc",    "application/x-freearc"},
        {".avi",    "video/x-msvideo"},
        {".azw",    "application/vnd.amazon.ebook"},
        {".bin",    "application/octet-stream"},
        {".bmp",    "image/bmp"},
        {".bz",     "application/x-bzip"},
        {".bz2",    "application/x-bzip2"},
        {".csh",    "application/x-csh"},
        {".css",    "text/css"},
        {".csv",    "text/csv"},
        {".doc",    "application/msword"},
        {".docx",   "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {".eot",    "application/vnd.ms-fontobject"},
        {".epub",   "application/epub+zip"},
        {".gif",    "image/gif"},
        {".htm",    "text/html"},
        {".html",   "text/html"},
        {".ico",    "image/vnd.microsoft.icon"},
        {".ics",    "text/calendar"},
        {".jar",    "application/java-archive"},
        {".jpeg",   "image/jpeg"},
        {".jpg",    "image/jpeg"},
        {".js",     "text/javascript"},
        {".json",   "application/json"},
        {".jsonld", "application/ld+json"},
        {".mid",    "audio/midi"},
        {".midi",   "audio/x-midi"},
        {".mjs",    "text/javascript"},
        {".mp3",    "audio/mpeg"},
        {".mpeg",   "video/mpeg"},
        {".mpkg",   "application/vnd.apple.installer+xml"},
        {".odp",    "application/vnd.oasis.opendocument.presentation"},
        {".ods",    "application/vnd.oasis.opendocument.spreadsheet"},
        {".odt",    "application/vnd.oasis.opendocument.text"},
        {".oga",    "audio/ogg"},
        {".ogv",    "video/ogg"},
        {".ogx",    "application/ogg"},
        {".otf",    "font/otf"},
        {".png",    "image/png"},
        {".pdf",    "application/pdf"},
        {".ppt",    "application/vnd.ms-powerpoint"},
        {".pptx",   "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
        {".rar",    "application/x-rar-compressed"},
        {".rtf",    "application/rtf"},
        {".sh",     "application/x-sh"},
        {".svg",    "image/svg+xml"},
        {".swf",    "application/x-shockwave-flash"},
        {".tar",    "application/x-tar"},
        {".tif",    "image/tiff"},
        {".tiff",   "image/tiff"},
        {".ttf",    "font/ttf"},
        {".txt",    "text/plain"},
        {".vsd",    "application/vnd.visio"},
        {".wav",    "audio/wav"},
        {".weba",   "audio/webm"},
        {".webm",   "video/webm"},
        {".webp",   "image/webp"},
        {".woff",   "font/woff"},
        {".woff2",  "font/woff2"},
        {".xhtml",  "application/xhtml+xml"},
        {".xls",    "application/vnd.ms-excel"},
        {".xlsx",   "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
        {".xml",    "application/xml"},
        {".xul",    "application/vnd.mozilla.xul+xml"},
        {".zip",    "application/zip"},
        {".3gp",    "video/3gpp"},
        {".3g2",    "video/3gpp2"},
        {".7z",     "application/x-7z-compressed"}
};

std::unordered_map<int, std::string> _statu_msg{
        {100, "Continue"},
        {101, "Switching Protocol"},
        {102, "Processing"},
        {103, "Early Hints"},
        {200, "OK"},
        {201, "Created"},
        {202, "Accepted"},
        {203, "Non-Authoritative Information"},
        {204, "No Content"},
        {205, "Reset Content"},
        {206, "Partial Content"},
        {207, "Multi-Status"},
        {208, "Already Reported"},
        {226, "IM Used"},
        {300, "Multiple Choice"},
        {301, "Moved Permanently"},
        {302, "Found"},
        {303, "See Other"},
        {304, "Not Modified"},
        {305, "Use Proxy"},
        {306, "unused"},
        {307, "Temporary Redirect"},
        {308, "Permanent Redirect"},
        {400, "Bad Request"},
        {401, "Unauthorized"},
        {402, "Payment Required"},
        {403, "Forbidden"},
        {404, "Not Found"},
        {405, "Method Not Allowed"},
        {406, "Not Acceptable"},
        {407, "Proxy Authentication Required"},
        {408, "Request Timeout"},
        {409, "Conflict"},
        {410, "Gone"},
        {411, "Length Required"},
        {412, "Precondition Failed"},
        {413, "Payload Too Large"},
        {414, "URI Too Long"},
        {415, "Unsupported Media Type"},
        {416, "Range Not Satisfiable"},
        {417, "Expectation Failed"},
        {418, "I'm a teapot"},
        {421, "Misdirected Request"},
        {422, "Unprocessable Entity"},
        {423, "Locked"},
        {424, "Failed Dependency"},
        {425, "Too Early"},
        {426, "Upgrade Required"},
        {428, "Precondition Required"},
        {429, "Too Many Requests"},
        {431, "Request Header Fields Too Large"},
        {451, "Unavailable For Legal Reasons"},
        {501, "Not Implemented"},
        {502, "Bad Gateway"},
        {503, "Service Unavailable"},
        {504, "Gateway Timeout"},
        {505, "HTTP Version Not Supported"},
        {506, "Variant Also Negotiates"},
        {507, "Insufficient Storage"},
        {508, "Loop Detected"},
        {510, "Not Extended"},
        {511, "Network Authentication Required"}
};

class Util {
public:
    static size_t Split(const std::string &src, const std::string &sep, std::vector<std::string> *array) {
        int offset = 0;
        while (offset < src.size()) {
            size_t pos = src.find(sep, offset);
            if (pos == std::string::npos) {
                if (pos == src.size()) break;
                array->push_back(src.substr(offset));
                return array->size();
            }
            if (pos == offset) {
                offset = pos + sep.size();
                continue;
            }
            array->push_back(src.substr(offset, pos - offset));
            offset = pos + sep.size();
        }
        return array->size();
    }

    static bool ReadFile(const std::string &filename, std::string *buf) {
        std::ifstream ifs(filename, std::ios::binary);
        if (!ifs.is_open()) {
            ERR_LOG("OPEN %s FILE FAILED!!", filename.c_str());
            return false;
        }
        size_t fsize;
        ifs.seekg(0, ifs.end);
        fsize = ifs.tellg();
        ifs.seekg(0, ifs.beg);
        buf->resize(fsize);
        ifs.read(&(*buf)[0], fsize);
        if (!ifs.good()) {
            ERR_LOG("READ %s File FAILED!!", filename.c_str());
            ifs.close();
            return false;
        }
        ifs.close();
        return true;
    }

    static bool WriteFile(const std::string &filename, const std::string &buf) {
        std::ofstream ofs(filename, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) {
            ERR_LOG("OPEN %s FILE FAILED!!", filename.c_str());
            return false;
        }
        ofs.write(buf.c_str(), buf.size());
        if (!ofs.good()) {
            ERR_LOG("Write %s FILE FAILED!!", filename.c_str());
            ofs.close();
            return false;
        }
        ofs.close();
        return true;
    }

    static std::string UrlEncode(const std::string url, bool convert_space_to_plus) {
        std::string res;
        for (auto &c: url) {
            if (c == '.' || c == '-' || c == '_' || c == '~' || std::isalnum(c)) {
                res += c;
            }
            if (c == ' ' && convert_space_to_plus) {
                res += ' ';
                continue;
            }
            char temp[4] = {0};
            snprintf(temp, 4, "%%%02X", c);
            res += temp;
        }
        return res;
    }

    static char HEXTOI(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'z') return c - 'a' + 10;
        if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
        return -1;
    }

    static std::string UrlDecode(const std::string url, bool convert_plus_to_space) {
        std::string res;
        for (int i = 0; i < url.size(); i++) {
            if (url[i] == '+' && convert_plus_to_space) {
                res += ' ';
                continue;
            }
            if (url[i] == '%' && (i + 2) < url.size()) {
                char v1 = HEXTOI(url[i + 1]);
                char v2 = HEXTOI(url[i + 2]);
                char v = (v1 << 4) + v2;
                res += v;
                i += 2;
                continue;
            }
            res += url[i];
        }
        return res;
    }

    static std::string StatuDesc(int statu) {
        auto it = _statu_msg.find(statu);
        if (it != _statu_msg.end()) {
            return it->second;
        }
        return "Unknow";
    }

    static std::string ExtMime(const std::string &filename) {
        size_t pos = filename.find_last_of(".");
        if (pos == std::string::npos) return "application/octet-stream";
        std::string ext = filename.substr(pos);
        auto it = _mime_msg.find(ext);
        if (it == _mime_msg.end()) return "application/octet-stream";
        return it->second;
    }

    static bool IsDirectory(const std::string &filename) {
        struct stat st;
        int ret = stat(filename.c_str(), &st);
        if (ret < 0) {
            return false;
        }
        return S_ISDIR(st.st_mode);
    }

    static bool IsRegular(const std::string &filename) {
        struct stat st;
        int ret = stat(filename.c_str(), &st);
        if (ret < 0) {
            return false;
        }
        return S_ISREG(st.st_mode);
    }

    static bool VaildPath(const std::string &path) {
        std::vector<std::string> subdir;
        Split(path, "/", &subdir);
        int level = 0;
        for (auto &dir: subdir) {
            if (dir == "..") {
                level--;
                if (level < 0) return false;
                continue;
            }
            level++;
        }
        return true;
    }
};

class HttpRequest {
public:
    std::string _method;
    std::string _path;
    std::string _version;
    std::string _boby;
    std::smatch _matches;
    std::unordered_map<std::string, std::string> _headers;
    std::unordered_map<std::string, std::string> _params;
public:
    HttpRequest() : _version("HTTP/1.1") {}

    void ReSet() {
        _method.clear();
        _path.clear();
        _version = "HTTP/1.1";
        _boby.clear();
        std::smatch match;
        _matches.swap(match);
        _headers.clear();
        _params.clear();
    }

    void SetHeader(const std::string &key, const std::string &val) { _headers.insert(std::make_pair(key, val)); }

    bool HasHeader(const std::string &key) const {
        auto it = _headers.find(key);
        if (it == _headers.end()) return false;
        return true;
    }

    std::string GetHeader(const std::string &key) const {
        auto it = _headers.find(key);
        if (it == _headers.end()) return "";
        return it->second;
    }

    void SetParam(std::string &key, std::string &val) { _params.insert(std::make_pair(key, val)); }

    bool HasParam(std::string &key) const {
        auto it = _params.find(key);
        if (it == _params.end()) return false;
        return true;
    }

    std::string GetParam(std::string &key) {
        auto it = _params.find(key);
        if (it == _params.end()) return "";
        return it->second;
    }

    size_t ContentLength() const {
        bool ret = HasHeader("Content-Length");
        if (!ret) {
            return 0;
        }
        std::string clen = GetHeader("Content-Length");
        return std::stol(clen);
    }

    bool Close() const {
        if (HasHeader("Connection") && GetHeader("Connection") == "keep-alive") return false;
        return true;
    }
};

class HttpResponse {
public:
    int _statu;
    bool _redirect_flag;
    std::string _redirect_url;
    std::string _body;
    std::unordered_map<std::string, std::string> _headers;
public:
    HttpResponse() : _redirect_flag(false), _statu(200) {}

    HttpResponse(int statu) : _redirect_flag(false), _statu(statu) {}

    void ReSet() {
        _statu = 200;
        _redirect_flag = false;
        _body.clear();
        _redirect_url.clear();
        _headers.clear();
    }

    void SetHeader(const std::string &key, const std::string &val) { _headers.insert(std::make_pair(key, val)); }

    bool HasHeader(const std::string &key) {
        auto it = _headers.find(key);
        if (it == _headers.end()) return false;
        return true;
    }

    std::string GetHeader(const std::string &key) {
        auto it = _headers.find(key);
        if (it == _headers.end()) return "";
        return it->second;
    }

    void SetContent(const std::string &body, const std::string &type) {
        _body = body;
        SetHeader("Content-Type", type);
    }

    void SetRedirect(std::string &url, int statu = 302) {
        _statu = statu;
        _redirect_flag = true;
        _redirect_url = url;
    }

    bool Close() {
        if (HasHeader("Connection") && GetHeader("Connection") == "keep-alive") return false;
        return true;
    }
};

using HttpRecvStatu = enum {
    RECV_HTTP_ERROR,
    RECV_HTTP_LINE,
    RECV_HTTP_HEAD,
    RECV_HTTP_BODY,
    RECV_HTTP_OVER
};

#define MAX_LINE 8192

class HttpContext {
private:
    int _resp_statu;
    HttpRecvStatu _recv_statu;
    HttpRequest _request;
private:

    bool ParseHttpLine(const std::string &line) {
        std::smatch matches;
        std::regex e("(GET|HEAD|POST|PUT|DELETE) ([^?]*)(?:\\?(.*))? (HTTP/1\\.[01])(?:\n|\r\n)?", std::regex::icase);
        bool ret = std::regex_match(line, matches, e);
        if (!ret) {
            _recv_statu = RECV_HTTP_ERROR;
            _resp_statu = 400;
            return false;
        }
        _request._method = matches[1];
        std::transform(_request._method.begin(), _request._method.end(), _request._method.begin(), ::toupper);
        _request._path = Util::UrlDecode(matches[2], false);
        _request._version = matches[4];
        std::vector<std::string> query_string_array;
        std::string query_string = matches[3];
        Util::Split(query_string, "&", &query_string_array);
        for (auto &str: query_string_array) {
            size_t pos = str.find('=');
            if (pos == std::string::npos) {
                _recv_statu = RECV_HTTP_ERROR;
                _resp_statu = 400;
                return false;
            }
            std::string key = Util::UrlDecode(str.substr(0, pos), true);
            std::string val = Util::UrlDecode(str.substr(pos + 1), true);
            _request.SetParam(key, val);
        }
        return true;
    }

    bool RecvHttpLine(Buffer *buf) {
        if (_recv_statu != RECV_HTTP_LINE) return false;
        std::string line = buf->GetLineAndPop();
        if (line.size() == 0) {
            if (buf->ReadAbleSize() > MAX_LINE) {
                _recv_statu = RECV_HTTP_ERROR;
                _resp_statu = 414;
                return false;
            }
            return true;
        }
        if (line.size() > MAX_LINE) {
            _recv_statu = RECV_HTTP_ERROR;
            _resp_statu = 414;
            return false;
        }
        bool ret = ParseHttpLine(line);
        if (!ret) return false;
        _recv_statu = RECV_HTTP_HEAD;
        return true;
    }

    bool RecvHttpHead(Buffer *buf) {
        if (_recv_statu != RECV_HTTP_HEAD) return false;
        while (1) {
            std::string line = buf->GetLineAndPop();
            if (line.size() == 0) {
                if (buf->ReadAbleSize() > MAX_LINE) {
                    _recv_statu = RECV_HTTP_ERROR;
                    _resp_statu = 414;
                    return false;
                }
                return true;
            }
            if (line.size() > MAX_LINE) {
                _recv_statu = RECV_HTTP_ERROR;
                _resp_statu = 414;
                return false;
            }
            if (line == "\n" || line == "\r\n") break;
            bool ret = ParseHttpHead(line);
            if (!ret) return false;
        }
        _recv_statu = RECV_HTTP_BODY;
        return true;
    }

    bool ParseHttpHead(std::string &line) {
        if (line.back() == '\n') line.pop_back();
        if (line.back() == '\r') line.pop_back();
        size_t pos = line.find(": ");
        if (pos == std::string::npos) {
            _recv_statu = RECV_HTTP_ERROR;
            _resp_statu = 400;
            return false;
        }
        std::string key = line.substr(0, pos);
        std::string val = line.substr(pos + 2);
        _request.SetHeader(key, val);
        return true;
    }

    bool RecvHttpBody(Buffer *buf) {
        if (_recv_statu != RECV_HTTP_BODY) return false;
        size_t content_length = _request.ContentLength();
        if (content_length == 0) {
            _recv_statu = RECV_HTTP_OVER;
            return true;
        }
        size_t real_len = content_length - _request._boby.size();
        if (buf->ReadAbleSize() >= real_len) {
            _request._boby.append(buf->ReadPosition(), real_len);
            buf->MoveReadOffset(real_len);
            _recv_statu = RECV_HTTP_OVER;
            return true;
        }
        _request._boby.append(buf->ReadPosition(), buf->ReadAbleSize());
        buf->MoveReadOffset(real_len);
        return true;
    }

public:
    HttpContext() : _resp_statu(200), _recv_statu(RECV_HTTP_LINE) {}

    void ReSet() {
        _resp_statu = 200;
        _recv_statu = RECV_HTTP_LINE;
        _request.ReSet();
    }

    int ResponseStatu() { return _resp_statu; }

    HttpRecvStatu RecvStatu() { return _recv_statu; }

    HttpRequest &Request() { return _request; }

    void RecvHttpRequest(Buffer *buf) {
        switch (_recv_statu) {
            case RECV_HTTP_LINE:
                RecvHttpLine(buf);
            case RECV_HTTP_HEAD:
                RecvHttpHead(buf);
            case RECV_HTTP_BODY:
                RecvHttpBody(buf);
        }
    }
};

class HttpServer {
private:
    using Handler = std::function<void(const HttpRequest &, HttpResponse *)>;
    using Handlers = std::vector<std::pair<std::regex, Handler>>;

    Handlers _get_route;
    Handlers _post_route;
    Handlers _put_route;
    Handlers _delete_route;
    std::string _basedir;
    TcpServer _server;
private:

    void ErrorHandler(const HttpRequest &req, HttpResponse *rsp) {
        std::string body;
        body += "<html>";
        body += "<head>";
        body += "<meta http-equiv='Content-Type' content='text/html;charset=utf-8'>";
        body += "</head>";
        body += "<body>";
        body += "<h1>";
        body += std::to_string(rsp->_statu);
        body += " ";
        body += Util::StatuDesc(rsp->_statu);
        body += "</h1>";
        body += "</body>";
        body += "</html>";
        rsp->SetContent(body, "text/html");
    }

    void WriteResponse(const PtrConnection &conn, const HttpRequest &req, HttpResponse &rsp) {
        if (req.Close()) {
            rsp.SetHeader("Connection", "close");
        } else {
            rsp.SetHeader("Connection", "keep-alive");
        }
        if (!rsp._body.empty() && !rsp.HasHeader("Content-Length")) {
            rsp.SetHeader("Content-Length", std::to_string(rsp._body.size()));
        }
        if (!rsp._body.empty() && !rsp.HasHeader("Content-Type")) {
            rsp.SetHeader("Content-Type", "application/octet-stream");
        }
        if (rsp._redirect_flag) {
            rsp.SetHeader("Location", rsp._redirect_url);
        }
        std::stringstream rsp_str;
        rsp_str << req._version << " " + std::to_string(rsp._statu) << " " << Util::StatuDesc(rsp._statu) << "\r\n";

        for (auto &head: rsp._headers) {
            rsp_str << head.first << ": " << head.second << "\r\n";
        }
        rsp_str << "\r\n";
        rsp_str << rsp._body;
        conn->Send(rsp_str.str().c_str(), rsp_str.str().size());
    }

    bool IsFileHandler(const HttpRequest &req) {
        if (_basedir.empty()) {
            return false;
        }
        if (req._method != "GET" && req._method != "HEAD") {
            return false;
        }

        if (Util::VaildPath(req._path) == false) {
            return false;
        }
        std::string req_path = _basedir + req._path;
        if (req._path.back() == '/') {
            req_path += "index.html";
        }
        if (Util::IsRegular(req_path) == false) {
            return false;
        }
        return true;
    }

    void FileHandler(const HttpRequest &req, HttpResponse *rsp) {
        std::string req_path = _basedir + req._path;
        if (req._path.back() == '/') {
            req_path += "index.html";
        }
        bool ret = Util::ReadFile(req_path, &rsp->_body);
        if (ret == false) {
            return;
        }
        std::string mime = Util::ExtMime(req_path);
        rsp->SetHeader("Content-Type", mime);
        return;
    }

    void Dispatcher(HttpRequest &req, HttpResponse *rsp, Handlers &handlers) {
        for (auto &handler: handlers) {
            const std::regex &re = handler.first;
            const Handler &functor = handler.second;
            bool ret = std::regex_match(req._path, req._matches, re);
            if (!ret) {
                continue;
            }
            return functor(req, rsp);
        }
        rsp->_statu = 404;
    }

    void Route(HttpRequest &req, HttpResponse *rsp) {
        if (IsFileHandler(req)) {
            return FileHandler(req, rsp);
        }
        if (req._method == "GET" || req._method == "HEAD") {
            return Dispatcher(req, rsp, _get_route);
        } else if (req._method == "POST") {
            return Dispatcher(req, rsp, _post_route);
        } else if (req._method == "PUT") {
            return Dispatcher(req, rsp, _put_route);
        } else if (req._method == "DELETE") {
            return Dispatcher(req, rsp, _delete_route);
        }
        rsp->_statu = 405;
    }

    void OnConnected(const PtrConnection &conn) {
        conn->SetContext(HttpContext());
        DBG_LOG("NEW CONNECTION %p Socekt %d Connid %d", conn.get(), conn->Fd(), conn->Id());
    }

    void OnMessage(const PtrConnection &conn, Buffer *buffer) {
        while (buffer->ReadAbleSize() > 0) {
            HttpContext *context = conn->GetContext()->get<HttpContext>();
            context->RecvHttpRequest(buffer);
            HttpRequest &req = context->Request();
            HttpResponse rsp(context->ResponseStatu());
            if (context->ResponseStatu() >= 400) {
                ErrorHandler(req, &rsp);
                WriteResponse(conn, req, rsp);
                context->ReSet();
                buffer->MoveReadOffset(buffer->ReadAbleSize());
                conn->Shutdown();
                return;
            }
            if (context->RecvStatu() != RECV_HTTP_OVER) {
                return;
            }
            Route(req, &rsp);
            WriteResponse(conn, req, rsp);
            context->ReSet();
            if (rsp.Close() == true) {
                conn->Shutdown();
            }
        }
    }

public:
    HttpServer(int port, int timeout = DEFAULT_TIMEOUT) : _server(port) {
        _server.EnableInactivateRelease(timeout);
        _server.SetConnectedCallback(std::bind(&HttpServer::OnConnected, this, std::placeholders::_1));
        _server.SetMessageCallback(
                std::bind(&HttpServer::OnMessage, this, std::placeholders::_1, std::placeholders::_2));
    }

    void SetBaseDir(const std::string &path) {
        assert(Util::IsDirectory(path));
        _basedir = path;
    }

    void Get(const std::string &pattern, const Handler &handler) {
        _get_route.push_back(std::make_pair(std::regex(pattern), handler));
    }

    void Post(const std::string &pattern, const Handler &handler) {
        _post_route.push_back(std::make_pair(std::regex(pattern), handler));
    }

    void Put(const std::string &pattern, const Handler &handler) {
        _put_route.push_back(std::make_pair(std::regex(pattern), handler));
    }

    void Delete(const std::string &pattern, const Handler &handler) {
        _delete_route.push_back(std::make_pair(std::regex(pattern), handler));
    }

    void SetThreadCount(int count) { _server.SetThreadCount(count); }

    void Listen() { _server.Start(); }
};

#endif //REACTOR_HTTP_H
