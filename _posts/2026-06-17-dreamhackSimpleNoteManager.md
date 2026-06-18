---
layout: single
title: "Dreamhack Simple Note Manager : 특수기능을 막는 이스케이프(\) "
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
published: false
---

<div class="notice--success">  
본 포스팅은 드림핵의 가이드라인을 준수하여 작성되었습니다. 전체 익스플로잇 스크립트나 FLAG 값은 포함하지 않으며, 취약점의 원리 분석과 방어 대책에 집중합니다.
</div>

안녕하세요! 오늘은 드림핵(Dreamhack)의 **Simple Note Manager** 문제를 풀어보며, 수많은 삽질 끝에 깊게 공부하게 된 **리눅스 쉘의 명령어 치환 기법**과 이를 제어하기 위한 **백슬래시(`\`) 이스케이프**의 핵심 원리를 공유해 보려고 합니다.

## 1. 주요 소스코드 분석

① 파일 백업 처리 함수
```python
def backup_notes(timestamp):
    with lock:
        #쓰기 모드로 실행 
        with open('./tmp/notes.tmp', 'w') as f:
            f.write(repr(notes))
            # 취약한 부분: {timestamp} 자리에 내가 넣은 값이 그대로 들어감!
        subprocess.Popen(f'cp ./tmp/notes.tmp /tmp/{timestamp}', shell=True) 
```
backup_notes 함수는 시스템 명령어를 실행하기 위해 subprocess.Popen을 호출합니다.  <br>
이때 인자로 들어가는 timestamp 변수가 포맷 스트링(f'...')을 통해 그대로 결합되는데, 결정적으로<font color='#ff4032'>shell=True</font> 옵션이 켜져 있습니다. <br> 즉, timestamp 내부에 리눅스 메타문자가 섞여 들어오면 그대로 OS 명령어로 실행되는 구조입니다.


```python
@app.route('/backup_notes', methods=['GET'])  # GET메소드
def get_backup_notes():
    print(len(notes), flush=True)
    if len(notes) == 0:
        abort(404)
    page = render_template('backup_notes.html')
    resp = make_response(page)
    resp.set_cookie('backup-timestamp', f'{time.time()}')  #현재시간의cookie가져옴
    return resp


@app.route('/backup_notes', methods=['POST'])
def post_backup_notes():
    if len(notes) == 0:
        abort(404)
    backup_timestamp = request.cookies.get('backup-timestamp', f'{time.time()}') #백업 버튼을 누르면 가져온 쿠기값을 backup_timestamp에 저장
    if not isinstance(backup_timestamp, str):
        abort(400)
    backup_notes(backup_timestamp)# backup_timestamp 값을 가지고 backup_notes실행, 즉 backup_timestamp에 스크립트 삽입
    return redirect(url_for('get_index')) 

```
/backup_notes 경로에 POST 요청을 보낼 때, 서버는 사용자가 전송한 backup-timestamp 쿠키 값을 그대로 가져와 backup_notes() 함수의 인자로 전달합니다. <br>

즉, 우리가 변조해야 할 핵심 타깃(공격 벡터)은 일반적인 Form 데이터나 URL 파라미터가 아니라 '쿠키(Cookie) 값'이라는 사실을 알 수 있습니다. <br> 단, 백업을 진행하려면 메모(notes)가 최소 1개 이상 존재해야 하므로 사전에 선행 작업이 필요합니다.

## 2. 가설 설정

### 1. 사전 조건 충족: 메모 생성 엔드포인트를 호출하여 len(notes) == 0 조건을 우회합니다.
{: .no_toc}

### 2. 쿠키 변조 공격: backup-timestamp 쿠키에 원격 명령 실행(RCE) 구문을 삽입하여 POST 요청을 전송합니다.
{: .no_toc}

### 3. 데이터 추출: curl 명령어를 활용하여 시스템 내부 명령의 결과값(cat flag)을 외부 RequestBin URL의 Body 데이터로 실어 보냅니다.
{: .no_toc}


사용하는 curl 옵션: 
-X: POST 메소드를 지정하고 요청할 URL을 지정하기 위한 옵션 입니다. <br>
-H: 전송할 헤더를 지정 할 수 있는 옵션입니다. (이 문제에서는 `400` 오류를 피하기 위해 사용하였습니다.) <br>
-d:  body 데이터를 기재하는 옵션입니다.  <br>
(뒤에 따옴표 없이 특수문자(중괄호와 백틱)가 오면 공백( )을 기준으로 인자(Argument)를 쪼개니 주의 하셔야 합니다.)




## 3. 핵심 원리: 명령어 치환과 로컬 PC 쉘의 함정

이 문제를 풀 때 가장 많은 고전과 시행착오를 겪게 만드는 주범은 바로 "명령어 치환" 메커니즘입니다. <br>
이 문제의 스크립트를 만들기 위해 저는 다음과 같은 문법에 대해 찾아보며 공부하였습니다.

1. `$()` : 명령어 치환이라는 특수 기능을 가지고 있는 문자입니다.

2. ` 백틱(``) ` : 백틱은 처번 문제에서 소개한바와 같이 명령어 치환이라는 특수기능을 가지고 있습니다.

3. 제가 겪은 거대한 삽질과 함정입니다.

### 실패하는 명령어 예시
{: .no_toc}

```bash
curl -X POST  -H "Cookie: $( 헤더지정  -d {``})"
```

저는 위와 같은 구조로 스크립트를 작성하였습니다.
그 결과 서버 설정 까지는 명령이 잘 들어 갔지만 가져오는 값은 제가 생각한 값들이 아니었습니다.

<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/simplenotemanager/empty.png' | relative_url }}"
       alt="{}"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[{}]</p>
</div>
출력:  

이유는 공격 대상인 문제 서버가 아니라 '내 로직을 입력한 내 로컬 PC'가 이 명령어를 먼저 읽어 실행했기 때문이었습니다. <br>
내 PC의 쉘이 전처리 과정에서 $()와 백틱을 먼저 실행해 버린 것입니다. 
내 PC에는 flag 파일이 없으므로 빈 값({}) 처리되어 최종적으로 문제 서버에는 아무런 명령도 없는 껍데기 요청만 전달된 것 입니다.


## 4. 해결 열쇠: 백슬래시(\) 이스케이프 (Escape)

 `백 슬래쉬(\)` : 이 친구를 찾기 참 힘들었습니다.
이 함정을 파쇄하기 위해 필요한 것이 바로 백슬래시(\)입니다.  <br>흔히 줄 바꿈이나 경로 구분자로 쓰이지만, 쉘 환경에서는 뒤에 오는 특수 메타문자의 기능을 일시적으로 증발시키고 단순한 '문자열'로 격하시키는<font color='#4ADE80'> 이스케이프</font> 기능을 수행합니다.

### 이스케이프 작동 원리 예시
{: .no_toc}
```bash
echo `date`   # 출력: 2026. 06. 17. (명령어 실행됨)
echo \`date\` # 출력: `date` (단순 문자열로 전달됨)
```

내 PC의 쉘이 명령어를 가로채지 못하도록 치환 문자 앞에 백슬래시(\)를 전부 붙여서 전송해야, 비로소 그 기호들이 훼손되지 않고 원본 그대로 드림핵 문제 서버 내부 subprocess.Popen(shell=True) 까지 도달하게 됩니다!



<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/simplenotemanager/flag.png' | relative_url }}"
       alt="{}"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[flag]</p>
</div>


## 5. Security coding

이전 글과 같이 이러한 보안 문제를 막기 위해서는 가장 먼저 할 수 있는 생각이 shell=False일 것 같습니다.

```python
import shutil

def backup_notes(timestamp):
    with lock:
        # 쓰기 모드로 파일 실행
        with open('./tmp/notes.tmp', 'w') as f:
            f.write(repr(notes))
```
외부 프로그램(cp)을 빌려 쓰지 말고, 파이썬의 shutil 라이브러리를 사용하면 코드를 딱 한 줄만으로 안전하게 바꿀 수 있습니다.

shutil.copy는 내부적으로 리눅스 쉘(/bin/sh)을 아예 실행하지 않고 시스템 콜을 직접 호출합니다.

우리가 앞서 성공했던 공격 코드 속의 $( )이나 백틱(`) 기호들은 리눅스 쉘이라는 환경이 존재해야만 명령어로 해석되어 작동하는 특수 기호들입니다.

하지만 위와 같이 파이썬 순수 코드로 대체해 버리면, 해커가 쿠키 값에 공격 기호를 아무리 섞어 보내도 쉘이 켜지지 않으므로 기호들이 터지지 않습니다. 서버는 그저 $(curl...)이라는 기호가 통째로 포함된 문자열을 '단순 파일 이름'으로 취급할 뿐입니다. 즉, 명령어 주입(Command Injection) 취약점이 원천 봉쇄됩니다.


<div style="text-align: center; margin: 20px 0;">
  <img src="{{ '/images/simplenotemanager/security.png' | relative_url }}"
       alt="{security}"
       style="max-width: 80%; height: auto; border: 1px solid #ddd; border-radius: 5px;">
  <p style="font-size: 0.9em; color: #ffffff;">[security]</p>
</div>




