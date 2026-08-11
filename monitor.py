import json
import os
import tarfile
from datetime import datetime
import io
import urllib.request
import feedparser  # pip install feedparser

# PyPI 신규 패키지 피드 및 상세 정보 API 기본 URL
PYPI_RSS_URL = "https://pypi.org/rss/packages.xml"
PYPI_JSON_API = "https://pypi.org/pypi/{package_name}/json"

# 악성 패키지 의심 키워드
SUSPICIOUS_KEYWORDS = [
    "base64.b64decode",
    "eval(",
    "exec(",
    "subprocess.Popen",
    "discord.com/api/webhooks",
    "socket.socket",
]


def get_download_url(package_name):
    """PyPI API를 통해 설치하지 않고 소스 코드 압축파일(.tar.gz) 주소만 가져온다."""
    try:
        url = PYPI_JSON_API.format(package_name=package_name)
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            # 소스 배포판(sdist)인 .tar.gz 파일의 URL 찾기
            for file_info in data.get("urls", []):
                if file_info.get("packagetype") == "sdist" and file_info.get("url").endswith(".tar.gz"):
                    return file_info.get("url")
    except Exception as e:
        print(f"❌ {package_name} API 조회 실패: {e}")
    return None


def analyze_package_code(download_url):
    """압축 파일을 메모리에 받아서 .py 파일들의 텍스트를 정적 분석한다."""
    evidences = []
    try:
        req = urllib.request.Request(download_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as response:
            # 메모리에 압축 파일 다운로드
            file_like_object = io.BytesIO(response.read())
            with tarfile.open(fileobj=file_like_object, mode="r:gz") as tar:
                # 압축 파일 내부의 파일들을 하나씩 검사
                for member in tar.getmembers():
                    if member.isfile() and member.name.endswith(".py"):
                        f = tar.extractfile(member)
                        if f:
                            content = f.read().decode("utf-8", errors="ignore")
                            # 라인별로 의심 키워드 탐지
                            lines = content.splitlines()
                            for line_num, line_content in enumerate(lines, 1):
                                for keyword in SUSPICIOUS_KEYWORDS:
                                    if keyword in line_content:
                                        evidences.append({
                                            "file": member.name,
                                            "line": line_num,
                                            "keyword_detected": keyword,
                                            "code_snippet": line_content.strip()
                                        })
    except Exception as e:
        print(f"❌ 소스 코드 다운로드/분석 중 에러: {e}")
    return evidences


def check_pypi_new_packages():
    feed = feedparser.parse(PYPI_RSS_URL)
    detected_list = []

    for entry in feed.entries[:10]:  # 최근 등록된 10개 패키지 순회
        package_name = entry.title.split()[0]
        print(f"🔍 검사 시작: {package_name}")

        # 1. 다운로드 URL 확보
        download_url = get_download_url(package_name)
        if not download_url:
            print(f"⏩ 소스 코드가 없는 패키지이므로 스킵한다: {package_name}")
            continue

        # 2. 정적 검사 실행하여 근거(Evidence) 추출
        evidences = analyze_package_code(download_url)

        # 3. 근거가 하나라도 발견되면 악성 의심으로 판단 및 기록
        if evidences:
            print(f"🚨 [위험] 의심스러운 패키지 감지됨: {package_name}")
            detected_list.append({
                "package_name": package_name,
                "checked_at": datetime.now().isoformat(),
                "download_url": download_url,
                "decision": "SUSPICIOUS",
                "evidences": evidences
            })
        else:
            print(f"🟢 [안전] {package_name} 특이사항 없음")

    # 4. 탐지된 데이터가 있다면 안전하게 JSON 파일로 저장
    if detected_list:
        os.makedirs("data", exist_ok=True)
        result_file = "data/detected_evidence.json"
        
        # 기존에 저장된 데이터가 있다면 이어붙이기(Append)
        existing_data = []
        if os.path.exists(result_file):
            try:
                with open(result_file, "r", encoding="utf-8") as f:
                    existing_data = json.load(f)
            except Exception:
                existing_data = []
        
        existing_data.extend(detected_list)
        
        with open(result_file, "w", encoding="utf-8") as f:
            json.dump(existing_data, f, indent=2, ensure_ascii=False)
        print(f"\n💾 총 {len(detected_list)}개의 악성 의심 근거가 '{result_file}'에 안전하게 누적 저장되었습니다!")


if __name__ == "__main__":
    check_pypi_new_packages()