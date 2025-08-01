import requests
import xml.etree.ElementTree as ET
import bz2
import re
from typing import List

# Константы для RHEL 8
OVAL_URL = "https://www.redhat.com/security/data/oval/v2/RHEL8/rhel-8.oval.xml.bz2"
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) "
        "Gecko/20100101 Firefox/115.0"
    )
}


def download_and_extract_oval(url: str) -> str:
    """
    Загружает и распаковывает OVAL-файл (bzip2)
    """
    try:
        print(f"Загрузка OVAL-файла: {url}")
        response = requests.get(url, headers=HEADERS, timeout=30)
        response.raise_for_status()

        decompressed = bz2.decompress(response.content)
        return decompressed.decode('utf-8')

    except requests.RequestException as e:
        print(f"Ошибка загрузки OVAL-файла: {e}")
    except bz2.BZ2Error as e:
        print(f"Ошибка распаковки bzip2: {e}")
    except Exception as e:
        print(f"Ошибка обработки OVAL-файла: {e}")
    return ""


def parse_oval_xml(xml_content: str) -> List[str]:
    """
    Парсит XML OVAL-файла и извлекает CVE
    """
    if not xml_content:
        return []

    try:
        print("Парсинг OVAL XML...")
        root = ET.fromstring(xml_content)

        ns = {
            'oval': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
            'red-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux'
        }
        cves = set()

        for definition in root.findall('.//oval:definition', ns):
            metadata = definition.find('oval:metadata', ns)
            if metadata is None:
                continue

            for ref in metadata.findall('oval:reference', ns):
                if ref.get('source') == 'CVE':
                    cve_id = ref.get('ref_id')
                    if cve_id and re.match(r'^CVE-\d{4}-\d{4,7}$', cve_id):
                        cves.add(cve_id)

            title = metadata.find('oval:title', ns)
            if title is not None and title.text:
                found = re.findall(r'CVE-\d{4}-\d{4,7}', title.text)
                cves.update(found)

        print(f"Найдено {len(cves)} уникальных CVE")
        return sorted(cves)

    except ET.ParseError as e:
        print(f"Ошибка парсинга XML: {e}")
    except Exception as e:
        print(f"Неожиданная ошибка при парсинге XML: {e}")
    return []


def save_results(filename: str, cves: List[str]) -> None:
    """
    Сохраняет список CVE в файл
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("\n".join(cves))
        print(f"Результаты сохранены в {filename}")
    except IOError as e:
        print(f"Ошибка сохранения файла: {e}")


def main() -> None:
    output = "RHEL8_bulletin.txt"

    print("=== Сбор CVE для Red Hat Enterprise Linux 8 ===")
    xml_data = download_and_extract_oval(OVAL_URL)
    cves = parse_oval_xml(xml_data)
    save_results(output, cves)
    print(f"Всего найдено {len(cves)} уязвимостей")


if __name__ == '__main__':
    main()
