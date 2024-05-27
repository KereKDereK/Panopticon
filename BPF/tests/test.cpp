#include <iostream>
#include <unistd.h>

int eblofon_initiated() {
	std::cout << "Eblofonizacia" << std::endl;
	sleep(3);
	return 1;
}


int main() {
	int times = 5;
	for(int i = 0; i < times; ++i){
		eblofon_initiated();
	}
	return times;
}
