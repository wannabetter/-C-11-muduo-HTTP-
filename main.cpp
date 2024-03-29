#include "HTTP/http.h"

std::string RequestStr(const HttpRequest &req) {
    std::stringstream ss;
    ss << req._method << " " << req._path << " " << req._version << "\r\n";
    for (auto &it: req._headers) {
        ss << it.first << ": " << it.second << "\r\n";
    }
    ss << "\r\n";
    ss << req._boby;
    return ss.str();
}

void Hello(const HttpRequest &req, HttpResponse *rsp) {
    rsp->SetContent(RequestStr(req), "text/plain");
}

void Login(const HttpRequest &req, HttpResponse *rsp) {
    rsp->SetContent(RequestStr(req), "text/plain");
}

void PutFile(const HttpRequest &req, HttpResponse *rsp) {
    rsp->SetContent(RequestStr(req), "text/plain");
}

void DelFile(const HttpRequest &req, HttpResponse *rsp) {
    rsp->SetContent(RequestStr(req), "text/plain");
}

int main() {
    HttpServer server(8085);
    server.SetThreadCount(32);
    server.SetBaseDir("/root/GaoSheng/");
    server.Get("/hello", Hello);
    server.Post("/login", Login);
    server.Put("/1234.txt", PutFile);
    server.Delete("/1234.txt", DelFile);
    server.Listen();
    return 0;
}