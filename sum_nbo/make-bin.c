#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>  // for htonl()

void write_bin_file(const char* filename, uint32_t value) {
    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        perror("파일 열기 실패");
        return;
    }

    uint32_t net_value = htonl(value);  // 호스트 → 네트워크 바이트 오더
    fwrite(&net_value, sizeof(uint32_t), 1, fp);

    fclose(fp);
    printf("%s 파일에 %u (0x%08X) 저장 완료\n", filename, value, value);
}

int main() {
    write_bin_file("one.bin", 1);
    write_bin_file("five-hundred.bin", 1);
    write_bin_file("thousand.bin", 1000);
    write_bin_file("30uk.bin", 3000000000);  // 30억
    write_bin_file("20uk.bin", 2000000000); // 20억 → 총합 50억 넘음!

    return 0;
}
