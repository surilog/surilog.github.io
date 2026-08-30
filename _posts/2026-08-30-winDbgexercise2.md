---
layout: single
title: '[Dreamhack] WinDbg Exercise 2 문제 풀이 및 파이썬 복호화 분석 노트'
sidebar:
  nav: "main"
tag : [Reversing, WinDbg, Dreamhack, Python, IDA, Assembly, Windows, x64]
categories: [System, CS]
toc : true
toc_sticky: true
toc_label: "Contents"
author_profile: true
search: true
comments: true
published: false
---

<div class="notice--info">
본 포스팅은 드림핵(Dreamhack) 리버스 엔지니어링 워게임인 <b>WinDbg Exercise 2</b>의 문제 풀이 기록입니다. 
IDA Pro를 활용한 정적 분석부터 Assembly 8비트 연산의 파이썬 스크립트 복호화 구현, 그리고 WinDbg의 조건부 중단점(Conditional Breakpoint)을 활용한 동적 플래그 추출 방식까지 종합적으로 정리했습니다.
</div>

---

# [Dreamhack] WinDbg Exercise 2 문제 풀이 및 분석 노트

## 1. 개요 및 정적 분석 (Static Analysis)

* **대상 파일**: `windbg_exercise.exe` (PDB 기호 파일 없음)
* **목표**: 사용자 입력값(`v9`)과 비교 검증되는 정답 플래그(FLAG) 추출

---

### IDA Pro 디컴파일 분석 (`main` 함수)

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
    __int64 v3;   // rbx - 루프 인덱스 (0 ~ 31)
    char v4;      // di  - 플래그 검증 성공 여부 (1: 참, 0: 거짓)
    char v5;      // al  - sub_140001000()의 반환값 (복호화된 플래그 1바이트)
    char v6;      // dl  - 임시 검증 플래그
    char *v7;     // rcx - 출력 메시지 포인터
    char v9[64];  // [rsp+20h] [rbp-58h] - 사용자 입력 버퍼

    sub_140001970("FLAG: ");
    sub_1400019D0("%32s");

    v3 = 0LL;
    v4 = 1;
    do
    {
        // byte_140003288 배열의 v3번째 바이트를 연산 함수에 전달
        v5 = sub_140001000(byte_140003288[v3]);
        v6 = 0;
        if ( v5 == v9[v3] ) // 복호화된 값(v5)과 사용자 입력(v9[v3]) 비교
            v6 = v4;
        ++v3;
        v4 = v6;
    }
    while ( v3 < 32 );

    v7 = "Correct!\n";
    if ( !v6 )
        v7 = "Wrong!\n";
    sub_140001970(v7);
    return 0;
}

```

#### 핵심 로직 요약

1. 프로그램은 사용자로부터 32바이트 길이의 문자열(`v9`)을 입력받습니다.
2. `v3` 인덱스를 `0`부터 `31`까지 1씩 증가시키며 `byte_140003288[v3]` 데이터를 `sub_140001000()` 연산 함수의 인자로 넘깁니다.
3. `sub_140001000()` 연산 결과 반환값인 `v5`와 입력 문자열 `v9[v3]`의 개별 문자를 일대일 비교합니다.
4. **결론**: `sub_140001000()` 함수가 순차적으로 반환하는 1바이트 문자의 합이 **정답 FLAG 문자열**입니다.

---

## 2. 문제 해결 전략 및 연산 검증

### Assembly 연산 및 8비트 마스킹 분석 (`rcx = 0x27`)

`sub_140001000()` 연산 어셈블리를 추적해 보면 8비트 레지스터(`al`)를 기반으로 연산이 수행됩니다.

```assembly
lea     eax, [rcx-30h]  ; eax = rcx - 0x30
xor     al, 0A4h        ; al  = al ^ 0xA4
add     al, 3Dh         ; al  = al + 0x3D
xor     al, 57h         ; al  = al ^ 0x57
add     al, 5Ch         ; al  = al + 0x5C
...
ret                     ; al 레지스터로 결과 반환

```

첫 번째 암호화 데이터인 `0x27`을 대입했을 때의 단계별 연산 과정:

1. **`lea eax, [rcx - 0x30]`**: $0x27 - 0x30 = -0x09 \rightarrow -0x09\ \&\ 0xFF = \mathbf{0xF7}$
2. **`xor al, 0xA4`**: $0xF7 \oplus 0xA4 = \mathbf{0x53}$
3. **`add al, 0x3D`**: $0x53 + 0x3D = \mathbf{0x90}$
4. **`xor al, 0x57`**: $0x90 \oplus 0x57 = \mathbf{0xC7}$
5. **`add al, 0x5C`**: $0xC7 + 0x5C = 0x123 \rightarrow 0x123\ \&\ 0xFF = \mathbf{0x23}$

---

## 3. 정답 플래그 추출 구현

### [방식 A] Python 자동화 복호화 스크립트

파이썬은 정수 포맷 오버플로우가 자동으로 무제한 확장되므로, 어셈블리의 8비트 레지스터 넘침 현상(Unsigned 8-bit Overflow)을 모사하기 위해 연산 단계마다 **`& 0xFF` 마스킹**을 적용하여 스크립트를 작성했습니다.

*  **전체 파이썬 스크립트 소스코드 (GitHub)**: [surilog/dreamhack - python_script.py](https://github.com/surilog/dreamhack/blob/main/Reversing/ReverseEngineering/WinDbg/WinDbg_exercise2/python_script.py)

---

### [방식 B] WinDbg 동적 분석 (ret 명령어가 실행되는 지점 중단점 설정)

디버깅 환경에서는 함수 반환 시점(`ret`)에서 `al` 레지스터의 값을 자동으로 출력(`.formats al`)하고 재개(`g`)하도록 중단점(Breakpoint)을 설정하면 플래그를 바로 추출할 수 있습니다.
<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/winDbg_exercise2/ret.png' | relative_url }}" 
       alt="ret오프셋" 
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #666;">[ret오프셋]</p>
</div>

* 상대주소(오프셋) = IDA'ret'주소 - IDA이미지베이스(0x140000000) => 0x14000194D-140000000 => 0x194D

```cmd
0:000> bp windbg_exercise+0x194d ".formats al; g"
0:000> g

```

#### WinDbg 실행 출력 결과

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/winDbg_exercise2/ret_c.png' | relative_url }}" 
       alt="WinDbg 실행 출력 결과" 
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #666;">[WinDbg 실행 출력 결과]</p>
</div>


### [방식 C] WinDbg 동적 분석 (main() 함수에서 call sub_140001000 다음 명령어가 실행되는 지점 중단점 설정)
---
sub_140001000() 함수 내부가 아닌, main() 함수 루프 안에서 call 명령어가 실행된 바로 다음 지점에 중단점을 설정하는 방식입니다. .printf 명령어를 활용하면 1바이트 반환값(al)을 단일 문자열 형태(%c)로 깔끔하게 연결하여 출력할 수 있습니다.

* 상대주소: 가상주소 0x140001A80 - IDA가 임의로 설정한 이미지 베이스(0x14000000) => 0x1A80
* 특징: 중단점에 도달할 때마다 반환값(rax 레지스터의 하위 1바이트 al)을 문자로 출력하고 디버깅을 계속 진행합니다.

#### WinDbg 실행 출력 결과

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/winDbg_exercise2/flag.png' | relative_url }}" 
       alt="flag출력" 
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #666;">[WinDbg 실행 출력 결과]</p>
</div>

## 4. 최종 결과 및 분석 회고

세 가지 방식(Python 스크립트, WinDbg ret 추적, WinDbg .printf 동적 출력) 모두 동일한 플래그 문자열을 명확하게 도출해냅니다.<br>

```text
DH{...}

```

### 풀이 방식별 비교 및 느낀 점
- **[방식 A] Python 스크립트**: 처음에는 어셈블리어 연산 흐름을 직접 파악하고 공부하기 위해 손연산을 시도했으나, 첫 입력값(0x27)부터 8비트 산술 변환 과정이 길어져 효율성을 위해 파이썬 스크립트로 오버플로우 연산을 모사하여 해결했습니다.<br>

- **[방식 B] WinDbg ret 지점 추적**: 함수가 끝나는 시점에 중단점을 걸어 값을 출력했지만, .formats al 특성상 Chars: ...D, Chars: ...H와 같이 개별 문자가 분리되어 출력되어 한눈에 플래그 문장을 조합하기엔 가독성이 다소 떨어지는 불편함이 있었습니다.<br>

- **[방식 C] WinDbg .printf 동적 출력 (추천)**: 드림핵 공식 풀이 방식이자 가장 효율적인 접근법이었습니다. call 직후 지점에서 .printf "%c", al 명령을 수행함으로써 32바이트의 반환값을 터미널에 한 줄의 완벽한 문장 형태(FLAG)로 이어붙여 출력해낼 수 있었습니다.<br>

- **결론**: 리버싱 문제 해결 시 단순 역산 스크립트 작성 방식에만 의존하기보다는, WinDbg의 조건부 중단점과 스크립팅 명령어를 유연하게 활용하는 것이 동적 분석 시간을 대폭 단축시킬 수 있음을 배운 실습이었습니다.