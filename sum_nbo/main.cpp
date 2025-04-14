#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>  // ntohl()

uint32_t read_network_order_value(const char* filename) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        perror("파일 열기 실패\n");
        exit(1);
    }

    uint32_t net_value;
    size_t bytes_read = fread(&net_value, 1, sizeof(uint32_t), fp);

    if (bytes_read < sizeof(uint32_t)) {
        fprintf(stderr, "파일 '%s' 크기 오류: 4바이트 미만입니다. (%zu 바이트)\n", filename, bytes_read);
        fclose(fp);
        exit(1);
    }

	int extra = fgetc(fp);  // 그 다음 바이트가 존재하는지 검사
    if (extra != EOF) {
        fprintf(stderr, "파일 '%s' 크기 오류: 4바이트 미만입니다. (%zu 바이트)\n", filename, bytes_read);
        fclose(fp);
        exit(1);
    }

    fclose(fp);
    return ntohl(net_value);  // 네트워크 바이트 오더 → 호스트 바이트 오더
}

int main(int argc, char* argv[]) {
    uint32_t sum = 0;
    for (int i = 1; i < argc; ++i) {
        uint32_t value = read_network_order_value(argv[i]);
        sum += value;

        printf("%d(0x%08X)", value, value);
        if (i + 1 == argc)
            printf(" = ");
        else
            printf(" + ");
    }

    printf("%d(0x%08X)\n", sum, sum);
    return 0;
}
