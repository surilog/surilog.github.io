---
layout: single
title: "Dreamhack Another Ping : 필터링 우회와 대응 방안 "
sidebar:
    nav: "main"
tag : [dreamhack, web, 웹 해킹, exploit, Command Injection]
categories: [wargame, 보안]
toc : true
toc_sticky: true
toc_label: "Contents"
author_profile: true
search: true
comments: true
published: true
---

<div class="notice--success">  
본 포스팅은 드림핵의 가이드라인을 준수하여 작성되었습니다. 전체 익스플로잇 스크립트나 FLAG 값은 포함하지 않으며, 취약점의 원리 분석과 방어 대책에 집중합니다.
</div>

오늘은 dreamhack의 Another Ping 문제를 살펴보면서  Command Injection 필터링 우회의 대응 방안에 대해 소개해 보려고 합니다.

## 1. 주요 소스코드 분석.

```python
#메타문자 필터링
FILTERED_CHARS = [' ', ';', '|', '&', '>', '<', '(', ')', '[', ']', '{', '}', '\n', '\r']


#ip가 타당한지 확인하는 함수
def is_valid_ip(ip):
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(ip_pattern, ip))

#필터링 검사 함수
def filter_input(user_input):
    for char in FILTERED_CHARS:
        if char in user_input:
            return False, f"Invalid character detected: {char}"
    return True, "OK"

def ping():
    ip = request.form.get('ip', '').strip()
    
    if not ip:
        return jsonify({'error': 'IP address is required'}), 400
    
    is_valid, message = filter_input(ip)
    if not is_valid:
        return jsonify({'error': message}), 400
    #ip가 들어와야 shell 활용이 가능!
    try:
        cmd = f"ping -c 4 {ip}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        #외부 시스템 명령이나 다른 프로그램을 실행하고, 해당 프로세스가 완료될 때가지 기다렸다가 결과를 반환
        return jsonify({
            'command': cmd,
            'stdout': result.stdout, # 명령어 입력에 따른 결과값 출력
            'stderr': result.stderr, #에러 메시지 출력
            'returncode': result.returncode
        })
    #Timeout시 실행
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Command timed out'}), 500
    #에러메시지를 노출 ==> 에러메시지를 통해 내부 정보 노출(취약점)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

```
### 코드 분석 포인트
{: .no_toc}
●**특수문자 차단**:공백( )을 비롯해 명령어를 이어주는 세미콜론(;), 파이프(|), 앰퍼샌드(&) 등의 메타문자를 강력하게 상쇄하고 있습니다.<br>
●**shell=True 인젝션 위험**: 외부 입력값(ip)이 cmd 문자열에 그대로 결합된 채 시스템 쉘에서 직접 실행되므로, 필터링만 우회하면 OS 명령어를 강제로 가동할 수 있습니다.<br>
●**에러 메시지 노출**: stderr 혹은 예외 처리 구문에서 에러 내용을 상세히 반환하므로, 이를 역이용한 에러 기반 정보 수집이 가능합니다.<br>

## 2. 가설설정(shell 활용)

### (1)시스템 shell true ==> 명령어 삽입 가능
{: .no_toc}

### (2)필터링이 많아 명령어 삽입 어려움 => 우회 필요
{: .no_toc}
공백: $IFS로 우회
ex. 8.8.8.8 && ls ==> 8.8.8.8$IFS&&IFSls

### (3)공백을 우회해도 명령어를 이어줄  ‘;’,‘|’,‘&’같은 메타문자들이 모두 필터링에 걸린다.
대안:**필터링에 없는 백틱(`)문자 활용!**
리눅스 쉘 환경에서 백틱은 명령어 대체 표현식으로, 쉘은 전체 명령을 수행하기 전 <font color='#4ADE80'>백틱 내부 구문을 가장 먼저 독립적으로 실행</font>합니다.<br>

●**백틱(`)우회의 3단계 작동 방법**
1단계 (선행 실행): 쉘이 내부의 `ls` 명령을 먼저 수행합니다. 결과값으로 현재 폴더 내부의 디렉터리 명인 `templates`가 도출됩니다.<br>
2단계 (인자 치환): 백틱 자리에 실행 결과인 templates가 그대로 대입되면서, 최종 실행 명령어가 ping -c 4 8.8.8.8 templates로 치환됩니다. (치환 과정에서 **공백 메커니즘이 자동으로 성립**됩니다.)<br>
3단계 (최종 명령 실행): 쉘은 완비된 ping 명령어를 구동합니다. 하지만 templates라는 호스트 네임은 존재하지 않으므로, 아래와 같이 에러 스트림(stderr)을 통해 내부 디렉터리명을 그대로 반환하게 됩니다.<br>

```json
Command: ping -c 4 8.8.8.8`ls`

=== STDOUT ===


=== STDERR ===
ping: templates: Name or service not known


Return Code: 2
```


## 3. 가설을 바탕으로 명령어 구문 생성

### (1) 도커 파일을 통해 /app 디렉터리 내 위치 확인
{: .no_toc}
도커 파일 설정을 통해 웹 서비스의 기본 구동 위치가 /app 디렉터리 내부에 있음을 알 수 있습니다.<br>

### (2) 8.8.8.8`ls`를 통해 명령어 작동 유무 확인
{: .no_toc}
앞서 세운 가설인 8.8.8.8`ls`주입을 통해 현재 경로 상에 templates 디렉터리가 있음을 에러 창 정보로 명확히 가려냈습니다.

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/anotherping/ls.png' | relative_url }}"
       alt="명령어 작동 성공"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[명령어 작동 성공]</p>
</div>

### (3) 혹시 모르니 pwd를 통해 현재 위치 확인
{: .no_toc}
현재 경로를 정확하게 파악하기 위해 8.8.8.8`pwd`를 주입했습니다.

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/anotherping/pwd.png' | relative_url }}"
       alt="현재 위치 확인"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[현재 위치 확인]</p>
</div>

### (4) 최종 단계: 플래그 구하기!
{: .no_toc}
<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/anotherping/flag.png' | relative_url }}"
       alt="플래그 확인"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[플래그 확인]</p>
</div>

**워게임의 재미를 위한 작은 선물!**
블로그를 찾아주신 독자분들이 직접 리눅스 쉘 변수의 경계선 규칙을 고민하고 실습해 보실 수 있도록, 최종 명령어 구문과 FLAG 값은 이미지에서 블러(가림) 처리해 두었습니다. 

앞서 설명해 드린 **"백틱 + $IFS + 특수 변수"**의 조합을 차근차근 적용해 보시면 여러분도 쉽게 에러 창에 나타나는 `DH{...}` 플래그를 획득하실 수 있을 겁니다!


## 4. 시큐어 코딩 방어 대책 (surl logic)

이번 **Another Ping** 문제는 공백이나 주요 메타문자를 차단하는 '블랙리스트' 방어 체계가 있더라도, 리눅스 쉘이 제공하는 백틱(`` ` ``)이나 환경 변수 파싱 특성을 이용하여 우회 가능하다는 것을 보여주는 문제였습니다.

안전한 웹 서비스를 구축하기 위해 백엔드 소스 코드 단에서 적용할 수 있는 핵심 보안 로직을 한 번 구상해 보았습니다.

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/anotherping/codesecurity.png' | relative_url }}"
       alt="코드 로직 수정"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[코드 로직 수정]</p>
</div>

1.`subprocess.run()` 함수를 리스트 형식으로 변경한 후 shell=False로 지정해주었습니다.
2. 명령어 입력에 따른 결과 값만 출력하여 공격자가 에러메시지를 보고 유추하지 못하도록 하였습니다.

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/anotherping/localip.png' | relative_url }}"
       alt="로컬 ip로 ping 확인"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[로컬ip로 ping 확인]</p>
</div>

Github Codespaces는 보안 정책상 외부망으로의 ICMP(Ping) 패킷 송수신이 차단되어 있기 때문에 8.8.8.8 입력 시 Command timed out이 발생 할 수 있습니다.<br>

저는 시큐어 코딩의 작동 여부를 검증하기 위해, 외부망을 타지 않는 로컬 루프백 주소인 127.0.0.1를 입력해서 정상적으로 출력이 나오는지 확인하였습니다.<br>

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/anotherping/securityls.png' | relative_url }}"
       alt="시큐어 코딩 성공"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[shell 명령 접근 불가]</p>
</div>

위와 같이 시스템 명령어가 보안 정책에 의해 막힌 것을 확인 할 수 있습니다.