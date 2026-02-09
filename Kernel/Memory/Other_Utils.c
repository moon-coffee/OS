#include <stddef.h>
#include <stdint.h>

static uint8_t *heap_end   = (uint8_t*)0x800000;
static uint8_t *heap_ptr   = (uint8_t*)0x100000;

void* malloc(size_t size) {
    if (heap_ptr + size > heap_end) return NULL;
    void* ptr = heap_ptr;
    heap_ptr += size;
    return ptr;
}

void free(void* ptr) {
    (void)ptr;
}

void* memcpy(void* dst, const void* src, size_t n){
    uint8_t* d = dst;
    const uint8_t* s = src;
    for(size_t i=0;i<n;i++) d[i]=s[i];
    return dst;
}

int strcmp(const char* a, const char* b){
    while(*a && *a==*b){ a++; b++; }
    return *(unsigned char*)a - *(unsigned char*)b;
}

int strncmp(const char* a, const char* b, size_t n){
    for(size_t i=0;i<n;i++){
        if(a[i]!=b[i] || a[i]==0) return (unsigned char)a[i] - (unsigned char)b[i];
    }
    return 0;
}

long strtol(const char *nptr, char **endptr, int base){
    (void)endptr; (void)base;
    long val = 0;
    while(*nptr>='0' && *nptr<='9'){
        val = val*10 + (*nptr - '0');
        nptr++;
    }
    return val;
}

double pow(double x, double y){
    double r = 1;
    int yi = (int)y;
    for(int i=0;i<yi;i++) r*=x;
    return r;
}

double ldexp(double x, int exp){
    while(exp>0){ x*=2; exp--; }
    while(exp<0){ x/=2; exp++; }
    return x;
}

int abs(int x){ return x<0?-x:x; }
