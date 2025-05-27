#include <queue>
#include <mutex>
#include <condition_variable>
#include <string>

class myQueue {
public:
    void enqueue(const std::string& msg);
    std::string dequeue();

private:
    std::queue<std::string> q_;
    std::mutex mutex_;
    std::condition_variable cv_;
};
