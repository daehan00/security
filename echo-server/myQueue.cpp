#include "myQueue.h"

void myQueue::enqueue(const std::string& msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    q_.push(msg);
    cv_.notify_one();
}

std::string myQueue::dequeue() {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this]{ return !q_.empty(); });
    std::string msg = q_.front();
    q_.pop();
    return msg;
}
