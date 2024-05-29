#include <iostream>
#include <chrono>
#include <thread>
#include <cstdlib>

const auto MAX_EXECUTION_TIME = std::chrono::seconds(2);

int main() {
    auto startTime = std::chrono::steady_clock::now();

    auto endTime = std::chrono::steady_clock::now();
    auto elapsedTime = endTime - startTime;

    if (elapsedTime > MAX_EXECUTION_TIME) {
        std::cerr << "Too much time elapsed. Abort..." << std::endl;
        return 1;
    }

    std::cout << "Success." << std::endl;
    return 0;
}