#include <iostream>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <cstring>

// Функция для вставки точек останова
void insertBreakpoints(std::vector<unsigned char>& code, int numBreakpoints) {
    std::srand(static_cast<unsigned int>(std::time(nullptr)));

    for (int i = 0; i < numBreakpoints; i++) {
        int position = std::rand() % (code.size() - 1);
        code.insert(code.begin() + position, 0xCC); // 0xCC - опкод int 3
    }
}

int main() {
    // Создание вектора для хранения кода функции main
    std::vector<unsigned char> mainFuncCode;

    // Получение адреса начала функции main
    unsigned char* mainFuncStart = reinterpret_cast<unsigned char*>(main);

    // Определение размера функции main
    unsigned char* endOfMainFunc = nullptr;
    for (unsigned char* p = mainFuncStart; *p != 0xC3; p++) { // 0xC3 - опкод ret
        mainFuncCode.push_back(*p);
        endOfMainFunc = p;
    }
    mainFuncCode.push_back(0xC3); // Добавление опкода ret в конец

    // Вставка точек останова
    int numBreakpoints = 1000; // Количество точек останова
    insertBreakpoints(mainFuncCode, numBreakpoints);

    // Выполнение модифицированного кода функции main
    void (*modifiedMain)() = reinterpret_cast<void(*)()>(mainFuncCode.data());
    modifiedMain();

    return 0;
}