//
// Created by DELL on 2024/3/15.
//

#ifndef REACTOR_SERVER_H
#define REACTOR_SERVER_H

#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <cstring>
#include <ctime>
#include <functional>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <typeinfo>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>

#define INF 0
#define DBG 1
#define ERR 2
#define LOG_LEVEL DBG

#define LOG(level, format, ...) do{\
        if (level < LOG_LEVEL) break;\
        time_t t = time(NULL);\
        struct tm *ltm = localtime(&t);\
        char tmp[32] = {0};\
        strftime(tmp, 31, "%F %H:%M:%S", ltm);\
        fprintf(stdout, "[%p %s %s:%d] " format "\n", (void*)pthread_self(), tmp, __FILE__, __LINE__, ##__VA_ARGS__);\
    }while(0)

#define INF_LOG(format, ...) LOG(INF, format, ##__VA_ARGS__)
#define DBG_LOG(format, ...) LOG(DBG, format, ##__VA_ARGS__)
#define ERR_LOG(format, ...) LOG(ERR, format, ##__VA_ARGS__)

#define BUFFER_DEFAULT_SIZE 1024

class Buffer {
private:
    std::vector<char> _buffer;
    uint64_t _reader_idx;
    uint64_t _writer_idx;
public:
    Buffer() : _reader_idx(0), _writer_idx(0), _buffer(BUFFER_DEFAULT_SIZE) {}

    char *Begin() { return &*_buffer.begin(); }

    char *WritePosition() { return Begin() + _writer_idx; }

    char *ReadPosition() { return Begin() + _reader_idx; }

    uint64_t TailIdleSize() { return _buffer.size() - _writer_idx; }

    uint64_t HeadIdleSize() { return _reader_idx; }

    uint64_t ReadAbleSize() { return _writer_idx - _reader_idx; }

    void MoveReadOffset(uint64_t len) {
        if (len == 0) return;
        assert(len <= ReadAbleSize());
        _reader_idx += len;
    }

    void MoveWriteOffset(uint64_t len) {
        assert(len <= TailIdleSize());
        _writer_idx += len;
    }

    void EnsureWriteSpace(uint64_t len) {

        if (TailIdleSize() >= len) { return; }

        if (len <= TailIdleSize() + HeadIdleSize()) {

            uint64_t rsz = ReadAbleSize();
            std::copy(ReadPosition(), ReadPosition() + rsz, Begin());
            _reader_idx = 0;
            _writer_idx = rsz;
        } else {
            DBG_LOG("RESIZE %ld", _writer_idx + len);
            _buffer.resize(_writer_idx + len);
        }
    }

    void Write(const void *data, uint64_t len) {
        if (len == 0) return;
        EnsureWriteSpace(len);
        const char *d = (const char *) data;
        std::copy(d, d + len, WritePosition());
    }

    void WriteAndPush(const void *data, uint64_t len) {
        Write(data, len);
        MoveWriteOffset(len);
    }

    void WriteString(const std::string &data) {
        return Write(data.c_str(), data.size());
    }

    void WriteStringAndPush(const std::string &data) {
        WriteString(data);
        MoveWriteOffset(data.size());
    }

    void WriteBuffer(Buffer &data) {
        return Write(data.ReadPosition(), data.ReadAbleSize());
    }

    void WriteBufferAndPush(Buffer &data) {
        WriteBuffer(data);
        MoveWriteOffset(data.ReadAbleSize());
    }

    void Read(void *buf, uint64_t len) {
        assert(len <= ReadAbleSize());
        std::copy(ReadPosition(), ReadPosition() + len, (char *) buf);
    }

    void ReadAndPop(void *buf, uint64_t len) {
        Read(buf, len);
        MoveReadOffset(len);
    }

    std::string ReadAsString(uint64_t len) {
        assert(len <= ReadAbleSize());
        std::string str;
        str.resize(len);
        Read(&str[0], len);
        return str;
    }

    std::string ReadAsStringAndPop(uint64_t len) {
        assert(len <= ReadAbleSize());
        std::string str = ReadAsString(len);
        MoveReadOffset(len);
        return str;
    }

    char *FindCRLF() {
        char *res = (char *) memchr(ReadPosition(), '\n', ReadAbleSize());
        return res;
    }

    std::string GetLine() {
        char *pos = FindCRLF();
        if (pos == NULL) {
            return "";
        }
        return ReadAsString(pos - ReadPosition() + 1);
    }

    std::string GetLineAndPop() {
        std::string str = GetLine();
        MoveReadOffset(str.size());
        return str;
    }

    void Clear() {
        _reader_idx = 0;
        _writer_idx = 0;
    }
};

#define MAX_LISTEN 1024

class Socket {
private:
    int _sockfd;
public:
    Socket() : _sockfd(-1) {}

    Socket(int fd) : _sockfd(fd) {

    }

    ~Socket() { Close(); }

    int Fd() { return _sockfd; }

    bool Create() {
        _sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (_sockfd < 0) {
            ERR_LOG("CREATE SOCKET FAILED!!");
            return false;
        }
        return true;
    }

    bool Bind(const std::string &ip, uint16_t port) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        socklen_t len = sizeof(struct sockaddr_in);
        int ret = bind(_sockfd, (struct sockaddr *) &addr, len);
        if (ret < 0) {
            ERR_LOG("BIND ADDRESS FAILED!");
            return false;
        }
        return true;
    }

    bool Listen(int backlog = MAX_LISTEN) {
        int ret = listen(_sockfd, backlog);
        if (ret < 0) {
            ERR_LOG("SOCKET LISTEN FAILED!");
            return false;
        }
        return true;
    }

    bool Connect(const std::string &ip, uint16_t port) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        socklen_t len = sizeof(struct sockaddr_in);
        int ret = connect(_sockfd, (struct sockaddr *) &addr, len);
        if (ret < 0) {
            ERR_LOG("CONNECT SERVER FAILED!");
            return false;
        }
        return true;
    }

    int Accept() {
        int newfd = accept(_sockfd, NULL, NULL);
        assert(newfd >= 0);
        if (newfd < 0) {
            ERR_LOG("SOCKET ACCEPT FAILED!");
            return -1;
        }
        return newfd;
    }

    ssize_t Recv(void *buf, size_t len, int flag = 0) {
        ssize_t ret = recv(_sockfd, buf, len, flag);
        if (ret <= 0) {
            if (errno == EAGAIN || errno == EINTR) {
                return 0;
            }
            ERR_LOG("SOCKET RECV FAILED!!");
            return -1;
        }
        return ret;
    }

    ssize_t NonBlockRecv(void *buf, size_t len) {
        return Recv(buf, len, MSG_DONTWAIT);
    }

    ssize_t Send(const void *buf, size_t len, int flag = 0) {
        ssize_t ret = send(_sockfd, buf, len, flag);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                return 0;
            }
            ERR_LOG("SOCKET SEND FAILED!!");
            return -1;
        }
        return ret;
    }

    ssize_t NonBlockSend(void *buf, size_t len) {
        if (len == 0) return 0;
        return Send(buf, len, MSG_DONTWAIT);
    }

    void Close() {
        if (_sockfd != -1) {
            close(_sockfd);
            _sockfd = -1;
        }
    }

    bool CreateServer(uint16_t port, const std::string &ip = "0.0.0.0", bool block_flag = false) {
        if (!Create()) return false;
        ReuseAddress();
        if (block_flag) NonBlock();
        if (!Bind(ip, port)) return false;
        if (!Listen()) return false;
        return true;
    }

    bool CreateClient(uint16_t port, const std::string &ip) {
        if (!Create()) return false;
        if (!Connect(ip, port)) return false;
        return true;
    }

    void ReuseAddress() {
        int val = 1;
        setsockopt(_sockfd, SOL_SOCKET, SO_REUSEADDR, (void *) &val, sizeof(int));
        val = 1;
        setsockopt(_sockfd, SOL_SOCKET, SO_REUSEPORT, (void *) &val, sizeof(int));
    }

    void NonBlock() {
        int flag = fcntl(_sockfd, F_GETFL, 0);
        fcntl(_sockfd, F_SETFL, flag | O_NONBLOCK);
    }
};

class Poller;

class EventLoop;

class Channel {
private:
    int _fd;
    EventLoop *_loop;
    uint32_t _events;
    uint32_t _revents;
    using EventCallback = std::function<void()>;
    EventCallback _read_callback;
    EventCallback _write_callback;
    EventCallback _error_callback;
    EventCallback _close_callback;
    EventCallback _event_callback;
public:
    Channel(EventLoop *loop, int fd) : _fd(fd), _events(0), _revents(0), _loop(loop) {}

    int Fd() { return _fd; }

    uint32_t Events() { return _events; }

    void SetREvents(uint32_t events) { _revents = events; }

    void SetReadCallback(const EventCallback &cb) { _read_callback = cb; }

    void SetWriteCallback(const EventCallback &cb) { _write_callback = cb; }

    void SetErrorCallback(const EventCallback &cb) { _error_callback = cb; }

    void SetCloseCallback(const EventCallback &cb) { _close_callback = cb; }

    void SetEventCallback(const EventCallback &cb) { _event_callback = cb; }

    bool ReadAble() { return (_events & EPOLLIN); }

    bool WriteAble() { return (_events & EPOLLOUT); }

    void EnableRead() {
        _events |= EPOLLIN;
        Update();
    }

    void EnableWrite() {
        _events |= EPOLLOUT;
        Update();
    }

    void DisableRead() {
        _events &= ~EPOLLIN;
        Update();
    }

    void DisableWrite() {
        _events &= ~EPOLLOUT;
        Update();
    }

    void DisableAll() {
        _events = 0;
        Update();
    }

    void Remove();

    void Update();

    void HandleEvent() {
        if ((_revents & EPOLLIN) || (_revents & EPOLLRDHUP) || (_revents & EPOLLPRI)) {
            if (_read_callback) { _read_callback(); }
        }
        if (_revents & EPOLLOUT) {
            if (_write_callback) _write_callback();
        } else if (_revents & EPOLLERR) {
            if (_error_callback) _error_callback();
        } else if (_revents & EPOLLHUP) {
            if (_close_callback) _close_callback();
        }
        if (_event_callback) _event_callback();
    }
};

#define MAX_EPOLLEVENTS 1024

class Poller {
private:
    int _epfd;
    struct epoll_event _evs[MAX_EPOLLEVENTS];
    std::unordered_map<int, Channel *> _channels;
private:
    void Update(Channel *channel, int op) {
        int fd = channel->Fd();
        struct epoll_event ev;
        ev.data.fd = fd;
        ev.events = channel->Events();
        int ret = epoll_ctl(_epfd, op, fd, &ev);
        if (ret < 0) {
            ERR_LOG("EPOLLCTL FAILED!");
        }
    }

    bool HasChannel(Channel *channel) {
        auto it = _channels.find(channel->Fd());
        if (it == _channels.end()) {
            return false;
        }
        return true;
    }

public:
    Poller() {
        _epfd = epoll_create(MAX_EPOLLEVENTS);
        if (_epfd < 0) {
            ERR_LOG("EPOLL CREATE FAILED!!");
            abort();
        }
        ERR_LOG("EPOLL %d", _epfd);
    }

    void UpdateEvent(Channel *channel) {
        bool ret = HasChannel(channel);
        if (ret == false) {
            _channels.insert(std::make_pair(channel->Fd(), channel));
            return Update(channel, EPOLL_CTL_ADD);
        }
        return Update(channel, EPOLL_CTL_MOD);
    }

    void RemoveEvent(Channel *channel) {
        auto it = _channels.find(channel->Fd());
        if (it != _channels.end()) {
            _channels.erase(it);
        }
        Update(channel, EPOLL_CTL_DEL);
    }

    void Poll(std::vector<Channel *> *active) {
        int nfds = epoll_wait(_epfd, _evs, MAX_EPOLLEVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR) {
                return;
            }
            ERR_LOG("EPOLL WAIT ERROR:%s\n", strerror(errno));
            abort();
        }
        for (int i = 0; i < nfds; i++) {
            auto it = _channels.find(_evs[i].data.fd);
            assert(it != _channels.end());
            it->second->SetREvents(_evs[i].events);
            active->push_back(it->second);
        }
    }
};

using TaskFunc = std::function<void()>;
using ReleaseFunc = std::function<void()>;

class TimerTask {
private:
    uint64_t _id;
    uint32_t _timeout;
    bool _canceled;
    TaskFunc _task_cb;
    ReleaseFunc _release;
public:
    TimerTask(uint64_t id, uint32_t delay, const TaskFunc &cb) :
            _id(id), _timeout(delay), _task_cb(cb), _canceled(false) {}

    ~TimerTask() {
        if (_canceled == false) _task_cb();
        _release();
    }

    void Cancel() { _canceled = true; }

    void SetRelease(const ReleaseFunc &cb) { _release = cb; }

    uint32_t DelayTime() { return _timeout; }
};

class TimerWheel {
private:
    using WeakTask = std::weak_ptr<TimerTask>;
    using PtrTask = std::shared_ptr<TimerTask>;
    int _tick;
    int _capacity;
    std::vector<std::vector<PtrTask>> _wheel;
    std::unordered_map<uint64_t, WeakTask> _timers;

    EventLoop *_loop;
    int _timerfd;
    std::unique_ptr<Channel> _timer_channel;
private:
    void RemoveTimer(uint64_t id) {
        auto it = _timers.find(id);
        if (it != _timers.end()) {
            _timers.erase(it);
        }
    }

    static int CreateTimerfd() {
        int timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (timerfd < 0) {
            ERR_LOG("TIMERFD CREATE FAILED!");
            abort();
        }
        ERR_LOG("TimerFd %d", timerfd);
        //int timerfd_settime(int fd, int flags, struct itimerspec *new, struct itimerspec *old);
        struct itimerspec itime;
        itime.it_value.tv_sec = 1;
        itime.it_value.tv_nsec = 0;
        itime.it_interval.tv_sec = 1;
        itime.it_interval.tv_nsec = 0;
        timerfd_settime(timerfd, 0, &itime, NULL);
        return timerfd;
    }

    int ReadTimefd() {
        uint64_t times;
        int ret = read(_timerfd, &times, 8);
        if (ret < 0) {
            ERR_LOG("READ TIMEFD FAILED!");
            abort();
        }
        return times;
    }

    void RunTimerTask() {
        _tick = (_tick + 1) % _capacity;
        _wheel[_tick].clear();
    }

    void OnTime() {
        int times = ReadTimefd();
        for (int i = 0; i < times; i++) {
            RunTimerTask();
        }
    }

    void TimerAddInLoop(uint64_t id, uint32_t delay, const TaskFunc &cb) {
        PtrTask pt(new TimerTask(id, delay, cb));
        pt->SetRelease(std::bind(&TimerWheel::RemoveTimer, this, id));
        int pos = (_tick + delay) % _capacity;
        _wheel[pos].push_back(pt);
        _timers[id] = WeakTask(pt);
    }

    void TimerRefreshInLoop(uint64_t id) {
        auto it = _timers.find(id);
        if (it == _timers.end()) {
            return;
        }
        PtrTask pt = it->second.lock();
        int delay = pt->DelayTime();
        int pos = (_tick + delay) % _capacity;
        _wheel[pos].push_back(pt);
    }

    void TimerCancelInLoop(uint64_t id) {
        auto it = _timers.find(id);
        if (it == _timers.end()) {
            return;
        }
        PtrTask pt = it->second.lock();
        if (pt) pt->Cancel();
    }

public:
    TimerWheel(EventLoop *loop) : _capacity(60), _tick(0), _wheel(_capacity), _loop(loop),
                                  _timerfd(CreateTimerfd()), _timer_channel(new Channel(_loop, _timerfd)) {
        _timer_channel->SetReadCallback(std::bind(&TimerWheel::OnTime, this));
        _timer_channel->EnableRead();
    }

    void TimerAdd(uint64_t id, uint32_t delay, const TaskFunc &cb);

    void TimerRefresh(uint64_t id);

    void TimerCancel(uint64_t id);

    bool HasTimer(uint64_t id) {
        auto it = _timers.find(id);
        if (it == _timers.end()) {
            return false;
        }
        return true;
    }
};

class EventLoop {
private:
    using Functor = std::function<void()>;
    std::thread::id _thread_id;
    int _event_fd;
    std::unique_ptr<Channel> _event_channel;
    Poller _poller;
    std::vector<Functor> _tasks;
    std::mutex _mutex;
    TimerWheel _timer_wheel;
public:
    void RunAllTask() {
        std::vector<Functor> functor;
        {
            std::unique_lock<std::mutex> _lock(_mutex);
            _tasks.swap(functor);
        }
        for (auto &f: functor) {
            f();
        }
        return;
    }

    static int CreateEventFd() {
        int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (efd < 0) {
            ERR_LOG("CREATE EVENTFD FAILED!!");
            abort();
        }
        ERR_LOG("EventFd %d", efd);
        return efd;
    }

    void ReadEventfd() {
        uint64_t res = 0;
        int ret = read(_event_fd, &res, sizeof(res));
        if (ret < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                return;
            }
            ERR_LOG("READ EVENTFD FAILED!");
            abort();
        }
        return;
    }

    void WeakUpEventFd() {
        uint64_t val = 1;
        int ret = write(_event_fd, &val, sizeof(val));
        if (ret < 0) {
            if (errno == EINTR) {
                return;
            }
            ERR_LOG("READ EVENTFD FAILED!");
            abort();
        }
        return;
    }

public:
    EventLoop() : _thread_id(std::this_thread::get_id()),
                  _event_fd(CreateEventFd()),
                  _event_channel(new Channel(this, _event_fd)),
                  _timer_wheel(this) {
        _event_channel->SetReadCallback(std::bind(&EventLoop::ReadEventfd, this));
        _event_channel->EnableRead();
    }

    void Start() {
        while (1) {
            std::vector<Channel *> actives;
            _poller.Poll(&actives);
            for (auto &channel: actives) {
                channel->HandleEvent();
            }
            RunAllTask();
        }
    }

    bool IsInLoop() {
        return (_thread_id == std::this_thread::get_id());
    }

    void AssertInLoop() {
        assert(_thread_id == std::this_thread::get_id());
    }

    void RunInLoop(const Functor &cb) {
        if (IsInLoop()) {
            return cb();
        }
        return QueueInLoop(cb);
    }

    void QueueInLoop(const Functor &cb) {
        {
            std::unique_lock<std::mutex> _lock(_mutex);
            _tasks.push_back(cb);
        }
        WeakUpEventFd();
    }

    void UpdateEvent(Channel *channel) { return _poller.UpdateEvent(channel); }

    void RemoveEvent(Channel *channel) { return _poller.RemoveEvent(channel); }

    void TimerAdd(uint64_t id, uint32_t delay, const TaskFunc &cb) { return _timer_wheel.TimerAdd(id, delay, cb); }

    void TimerRefresh(uint64_t id) { return _timer_wheel.TimerRefresh(id); }

    void TimerCancel(uint64_t id) { return _timer_wheel.TimerCancel(id); }

    bool HasTimer(uint64_t id) { return _timer_wheel.HasTimer(id); }
};

class LoopThread {
private:
    std::mutex _mutex;
    std::condition_variable _cond;
    EventLoop *_loop;
    std::thread _thread;
private:
    void ThreadEntry() {
        EventLoop loop;
        {
            std::unique_lock<std::mutex> lock(_mutex);
            _loop = &loop;
            _cond.notify_all();
        }
        loop.Start();
    }

public:
    LoopThread() : _loop(nullptr), _thread(std::thread(&LoopThread::ThreadEntry, this)) {}

    EventLoop *GetLoop() {
        EventLoop *loop = nullptr;
        {
            std::unique_lock<std::mutex> lock(_mutex);
            _cond.wait(lock, [&]() { return _loop != nullptr; });
            loop = _loop;
        }
        return loop;
    }

};

class LoopThreadPool {
private:
    int _thread_count;
    int _next_idx;
    EventLoop *_baseloop;
    std::vector<LoopThread *> _threads;
    std::vector<EventLoop *> _loops;
public:
    LoopThreadPool(EventLoop *base_loop) : _thread_count(0), _next_idx(0), _baseloop(base_loop) {}

    void SetThreadCount(int count) { _thread_count = count; }

    void Create() {
        if (_thread_count > 0) {
            _threads.resize(_thread_count);
            _loops.resize(_thread_count);
            for (int i = 0; i < _thread_count; i++) {
                _threads[i] = new LoopThread();
                _loops[i] = _threads[i]->GetLoop();
            }
        }
    }

    EventLoop *NextLoop() {
        if (_thread_count == 0) return _baseloop;
        _next_idx = (_next_idx + 1) % _thread_count;
        return _loops[_next_idx];
    }
};

class Any {
private:
    class holder {
    public:
        virtual ~holder() {}

        virtual const std::type_info &type() = 0;

        virtual holder *clone() = 0;
    };

    template<class T>
    class placeholder : public holder {
    public:
        placeholder(const T &val) : _val(val) {}

        // 获取子类对象保存的数据类型
        virtual const std::type_info &type() { return typeid(T); }

        // 针对当前的对象自身，克隆出一个新的子类对象
        virtual holder *clone() { return new placeholder(_val); }

    public:
        T _val;
    };

    holder *_content;
public:
    Any() : _content(NULL) {}

    template<class T>
    Any(const T &val):_content(new placeholder<T>(val)) {}

    Any(const Any &other) : _content(other._content ? other._content->clone() : NULL) {}

    ~Any() { delete _content; }

    Any &swap(Any &other) {
        std::swap(_content, other._content);
        return *this;
    }

    // 返回子类对象保存的数据的指针
    template<class T>
    T *get() {
        //想要获取的数据类型，必须和保存的数据类型一致
        assert(typeid(T) == _content->type());
        return &((placeholder<T> *) _content)->_val;
    }

    //赋值运算符的重载函数
    template<class T>
    Any &operator=(const T &val) {
        //为val构造一个临时的通用容器，然后与当前容器自身进行指针交换，临时对象释放的时候，原先保存的数据也就被释放
        Any(val).swap(*this);
        return *this;
    }

    Any &operator=(const Any &other) {
        Any(other).swap(*this);
        return *this;
    }
};

using ConnStatu = enum ConnStatu {
    DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING
};

class Connection;

using PtrConnection = std::shared_ptr<Connection>;

class Connection : public std::enable_shared_from_this<Connection> {
private:
    uint64_t _conn_id;
    int _sockfd;
    bool _enable_inactivate_release;
    EventLoop *_loop;
    ConnStatu _statu;
    Socket _socket;
    Channel _channel;
    Buffer _in_buffer, _out_buffer;
    Any _context;

    using ConnnectCallback = std::function<void(const PtrConnection &)>;
    using MessageCallback = std::function<void(const PtrConnection &, Buffer *)>;
    using CloseCallback = std::function<void(const PtrConnection &)>;
    using AnyEventCallback = std::function<void(const PtrConnection &)>;

    ConnnectCallback _connect_callback;
    MessageCallback _message_callback;
    CloseCallback _close_callback;
    AnyEventCallback _event_callback;
    CloseCallback _server_close_callback;
private:

    void HandleRead() {
        char buf[65536] = {0};
        ssize_t ret = _socket.NonBlockRecv(buf, 65535);
        if (ret < 0) {
            return ShutdownInLoop();
        }
        _in_buffer.WriteAndPush(buf, ret);
        if (_in_buffer.ReadAbleSize() > 0) {
            return _message_callback(shared_from_this(), &_in_buffer);
        }
    }

    void HandleWrite() {
        ssize_t ret = _socket.NonBlockSend(_out_buffer.ReadPosition(), _out_buffer.ReadAbleSize());
        if (ret < 0) {
            if (_in_buffer.ReadAbleSize() > 0) {
                _message_callback(shared_from_this(), &_in_buffer);
            }
            return Release();
        }
        _out_buffer.MoveReadOffset(ret);
        if (_out_buffer.ReadAbleSize() == 0) {
            _channel.DisableWrite();
            if (_statu == DISCONNECTING) {
                return Release();
            }
        }
    }

    void HandleClose() {
        if (_in_buffer.ReadAbleSize() > 0) {
            _message_callback(shared_from_this(), &_in_buffer);
        }
        return Release();
    }

    void HandleError() {
        HandleClose();
    }

    void HandleEvent() {
        if (_enable_inactivate_release) _loop->TimerRefresh(_conn_id);
        if (_event_callback) _event_callback(shared_from_this());
    }

    void EstablishedInLoop() {
        assert(_statu == CONNECTING);
        _statu = CONNECTED;
        _channel.EnableRead();
        if (_connect_callback) _connect_callback(shared_from_this());
    }

    void ReleaseInLoop() {
        _statu = DISCONNECTED;
        _channel.Remove();
        _socket.Close();
        if (_loop->HasTimer(_conn_id)) {
            CancelInactivateReleaseInLoop();
        }
        if (_close_callback) _close_callback(shared_from_this());
        if (_server_close_callback) _server_close_callback(shared_from_this());
    }

    void Release() {
        _loop->QueueInLoop(std::bind(&Connection::ReleaseInLoop, this));
    }

    void SendInLoop(Buffer &buf) {
        if (_statu == DISCONNECTED) return;
        _out_buffer.WriteBufferAndPush(buf);
        if (!_channel.WriteAble()) {
            _channel.EnableWrite();
        }
    }

    void ShutdownInLoop() {
        _statu = DISCONNECTING;
        if (_in_buffer.ReadAbleSize() > 0) {

            if (_message_callback) _message_callback(shared_from_this(), &_in_buffer);
        }
        if (_out_buffer.ReadAbleSize() > 0) {
            if (_channel.WriteAble() == false) {
                _channel.EnableWrite();
            }
        }
        if (_out_buffer.ReadAbleSize() == 0) {
            Release();
        }
    }

    void EnableInactivateReleaseInLoop(int sec) {
        _enable_inactivate_release = true;
        if (_loop->HasTimer(_conn_id)) return _loop->TimerRefresh(_conn_id);
        _loop->TimerAdd(_conn_id, sec, std::bind(&Connection::ReleaseInLoop, this));
    }

    void CancelInactivateReleaseInLoop() {
        _enable_inactivate_release = false;
        if (_loop->HasTimer(_conn_id)) return _loop->TimerCancel(_conn_id);
    }

    void UpgradeInLoop(const Any &context, const ConnnectCallback &conn, const MessageCallback &msg,
                       const CloseCallback &closed,
                       const AnyEventCallback &event) {
        _context = context;
        _connect_callback = conn;
        _message_callback = msg;
        _close_callback = closed;
        _event_callback = event;
    }

public:
    Connection(EventLoop *loop, uint64_t conn_id, int sockfd) :
            _conn_id(conn_id), _sockfd(sockfd),
            _enable_inactivate_release(false),
            _loop(loop), _statu(CONNECTING),
            _socket(_sockfd), _channel(loop, _sockfd) {
        _channel.SetCloseCallback(std::bind(&Connection::HandleClose, this));
        _channel.SetEventCallback(std::bind(&Connection::HandleEvent, this));
        _channel.SetReadCallback(std::bind(&Connection::HandleRead, this));
        _channel.SetWriteCallback(std::bind(&Connection::HandleWrite, this));
        _channel.SetErrorCallback(std::bind(&Connection::HandleError, this));
    }

    ~Connection() { DBG_LOG("RELEASE CONNTION %p, Socket %d", this, _channel.Fd()); }

    int Fd() { return _sockfd; }

    int Id() { return _conn_id; }

    bool Connected() { return _statu == CONNECTED; }

    void SetContext(const Any &context) { _context = context; }

    Any *GetContext() { return &_context; }

    void SetConnectCallback(const ConnnectCallback &cb) { _connect_callback = cb; }

    void SetMessageCallback(const MessageCallback &cb) { _message_callback = cb; }

    void SetCloseCallback(const CloseCallback &cb) { _connect_callback = cb; }

    void SetAnyEventCallback(const AnyEventCallback &cb) { _event_callback = cb; }

    void SetSevClosedCallback(const CloseCallback &cb) { _server_close_callback = cb; }

    void Established() { _loop->RunInLoop(std::bind(&Connection::EstablishedInLoop, this)); }

    void Send(const char *data, size_t len) {
        Buffer buf;
        buf.WriteAndPush(data, len);
        _loop->RunInLoop(std::bind(&Connection::SendInLoop, this, std::move(buf)));
    }

    void Shutdown() { _loop->RunInLoop(std::bind(&Connection::ShutdownInLoop, this)); }

    void EnableInactivateRelease(int sec) {
        _loop->RunInLoop(std::bind(&Connection::EnableInactivateReleaseInLoop, this, sec));
    }

    void CancelInactivateRelease() {
        _loop->RunInLoop(std::bind(&Connection::CancelInactivateReleaseInLoop, this));
    }

    void Upgrade(const Any &context, const ConnnectCallback &conn, const MessageCallback &msg,
                 const CloseCallback &closed,
                 const AnyEventCallback &event) {
        _loop->AssertInLoop();
        _loop->RunInLoop(std::bind(&Connection::UpgradeInLoop, this, context, conn, msg, closed, event));
    }
};

class Acceptor {
private:
    Socket _socket;
    EventLoop *_loop;
    Channel _channel;

    using AcceptCallback = std::function<void(int)>;
    AcceptCallback _accept_callback;
private:
    void HandleRead() {
        int newfd = _socket.Accept();
        if (newfd < 0) {
            return;
        }
        if (_accept_callback) _accept_callback(newfd);
    }

    int CreateServer(int port) {
        bool ret = _socket.CreateServer(port);
        assert(ret == true);
        return _socket.Fd();
    }

public:
    Acceptor(EventLoop *loop, int port) : _socket(CreateServer(port)), _loop(loop), _channel(loop, _socket.Fd()) {
        ERR_LOG("Acceptor %d", _socket.Fd());
        _channel.SetReadCallback(std::bind(&Acceptor::HandleRead, this));
    }

    void SetAcceptCallback(const AcceptCallback &cb) { _accept_callback = cb; }

    void Listen() { _channel.EnableRead(); }

};

class TcpServer {
private:
    uint64_t _next_id;
    int _port;
    int _timeout;
    bool _enable_inactivate_release;
    EventLoop _baseloop;
    Acceptor _acceptor;
    LoopThreadPool _pool;
    std::unordered_map<uint64_t, PtrConnection> _conns;

    using ConnnectCallback = std::function<void(const PtrConnection &)>;
    using MessageCallback = std::function<void(const PtrConnection &, Buffer *)>;
    using CloseCallback = std::function<void(const PtrConnection &)>;
    using AnyEventCallback = std::function<void(const PtrConnection &)>;
    using Functor = std::function<void()>;

    ConnnectCallback _connect_callback;
    MessageCallback _message_callback;
    CloseCallback _close_callback;
    AnyEventCallback _event_callback;
private:
    void NewConnection(int fd) {
        _next_id++;
        PtrConnection conn(new Connection(_pool.NextLoop(), _next_id, fd));
        conn->SetMessageCallback(_message_callback);
        conn->SetCloseCallback(_close_callback);
        conn->SetConnectCallback(_connect_callback);
        conn->SetAnyEventCallback(_event_callback);
        conn->SetSevClosedCallback(std::bind(&TcpServer::RemoveConnection, this, std::placeholders::_1));
        if (_enable_inactivate_release) conn->EnableInactivateRelease(_timeout);
        conn->Established();
        _conns.insert(std::make_pair(_next_id, conn));
    }

    void RemoveConnectionInLoop(const PtrConnection &conn) {
        int id = conn->Id();
        auto it = _conns.find(id);
        if (it != _conns.end()) {
            _conns.erase(it);
        }
    }

    void RemoveConnection(const PtrConnection &conn) {
        _baseloop.RunInLoop(std::bind(&TcpServer::RemoveConnectionInLoop, this, conn));
    }

    void RunAfterInLoop(const Functor &task, int delay) {
        _next_id++;
        _baseloop.TimerAdd(_next_id, delay, task);
    }

public:
    TcpServer(int port) : _port(port), _next_id(0),
                          _enable_inactivate_release(false),
                          _acceptor(&_baseloop, _port),
                          _pool(&_baseloop) {
        _acceptor.SetAcceptCallback(std::bind(&TcpServer::NewConnection, this, std::placeholders::_1));
        _acceptor.Listen();
    }

    void SetThreadCount(int count) { _pool.SetThreadCount(count); }

    void SetConnectedCallback(const ConnnectCallback &cb) { _connect_callback = cb; }

    void SetMessageCallback(const MessageCallback &cb) { _message_callback = cb; }

    void SetCloseCallback(const CloseCallback &cb) { _connect_callback = cb; }

    void SetAnyEventCallback(const AnyEventCallback &cb) { _event_callback = cb; }

    void EnableInactivateRelease(int timeout) {
        _timeout = timeout;
        _enable_inactivate_release = true;
    }

    void RunAfter(const Functor &task, int delay) {
        _baseloop.RunInLoop(std::bind(&TcpServer::RunAfterInLoop, this, task, delay));
    }

    void Start() {
        _pool.Create();
        _baseloop.Start();
    }

};

void Channel::Remove() { return _loop->RemoveEvent(this); }

void Channel::Update() { return _loop->UpdateEvent(this); }

void TimerWheel::TimerAdd(uint64_t id, uint32_t delay, const TaskFunc &cb) {
    _loop->RunInLoop(std::bind(&TimerWheel::TimerAddInLoop, this, id, delay, cb));
}

void TimerWheel::TimerRefresh(uint64_t id) {
    _loop->RunInLoop(std::bind(&TimerWheel::TimerRefreshInLoop, this, id));
}

void TimerWheel::TimerCancel(uint64_t id) {
    _loop->RunInLoop(std::bind(&TimerWheel::TimerCancelInLoop, this, id));
}

class NetWork {
public:
    NetWork() {
        DBG_LOG("SIGPIPI INIT");
        signal(SIGPIPE, SIG_IGN);
    }
};

static NetWork nw;

#endif //REACTOR_SERVER_H
