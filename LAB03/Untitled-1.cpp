#include <iostream>
#include <fstream>
#include <string>

using namespace std;

void GenerateFile(const string& filename, size_t size) {
    ofstream out(filename, ios::binary);
    if (!out) {
        cerr << "Cannot open file: " << filename << endl;
        return;
    }

    // Nội dung mẫu: 'A', 'B', 'C', ... lặp lại
    string content;
    char ch = 'A';
    for (size_t i = 0; i < size; ++i) {
        content += ch;
        ch = (ch == 'Z') ? 'A' : ch + 1;
    }

    out.write(content.c_str(), content.size());
    out.close();

    cout << "Generated " << filename << " with size " << size << " bytes." << endl;
}

int main() {
    GenerateFile("plain100.txt", 100);
    GenerateFile("plain200.txt", 200);
    GenerateFile("plain300.txt", 300);
    return 0;
}
