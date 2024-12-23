# System ekstrakcji danych z plików PCAP

## Opis projektu

Aplikacja CLI w Pythonie umożliwiająca analizę i ekstrakcję danych z plików `.pcap`.  
Pozwala na wybór jednego lub wielu plików, filtrowanie konkretnych rodzajów ruchu (DNS, TCP, HTTP),  
automatyczne oznaczanie kierunku ruchu (incoming/outgoing) oraz zapisywanie zebranych danych w bazie SQLite.  
Dodatkowo możliwe jest zarchiwizowanie bazy `.db` do pliku `.zip` z hasłem, zabezpieczonego szyfrowaniem AES.

## Kluczowe funkcje

- **Interaktywne CLI**: krok po kroku prowadzi użytkownika przez wybór plików `.pcap`, filtrów (DNS, TCP, HTTP) oraz nazwę bazy danych.  
- **Scapy**: obsługa parsowania i analizy ruchu sieciowego.  
- **SQLite**: dane o pakietach (czas, adresy IP, protokół, porty, kierunek) zapisywane są w lokalnej bazie `packets` (domyślnie `nazwa.db`).  
- **Archiwizacja z hasłem**: możliwość zabezpieczenia pliku `.db` za pomocą archiwum ZIP z hasłem (biblioteka `pyzipper`).  
- **Wielokrotne uruchomienie**: aplikacja może przeprowadzać wiele analiz w jednym uruchomieniu, pytając użytkownika, czy chce kontynuować.

## Wymagania

- **Python 3.7+**  
- Biblioteki Python:  
  - `scapy` (parsowanie pakietów sieciowych)  
  - `pyzipper` (tworzenie zaszyfrowanego archiwum ZIP)  
- (Opcjonalnie) Visual C++ Build Tools na Windows, jeśli instalacja bibliotek wymaga kompilacji (zazwyczaj `pyzipper` ma dostępne binarne paczki *wheels* i nie wymaga kompilowania).

## Instalacja

1. Zainstaluj Pythona (3.7+).  
2. (Opcjonalnie) utwórz wirtualne środowisko:
   ```bash
   python -m venv venv
   source venv/bin/activate    # Linux/Mac
   # lub:
   venv\Scripts\activate       # Windows
   ```
3. Zainstaluj wymagane biblioteki:
   ```bash
   pip install -r requirements.txt
   ```
4. Upewnij się, że w folderze znajdują się pliki `.pcap`, które chcesz przeanalizować.

## Uruchomienie

1. W konsoli/terminalu przejdź do katalogu projektu:
   ```bash
   cd sciezka/do/projektu
   ```
2. Uruchom główny skrypt (np. `pcap_cli_app.py`):
   ```bash
   python pcap_cli_app.py
   ```
3. Postępuj zgodnie z instrukcjami w CLI:
   - Wybierz plik/plik(i) `.pcap` z listy.
   - Wskaż rodzaj ruchu do wyekstrahowania (DNS, TCP, HTTP, wszystko).
   - Domyślnie baza danych przyjmuje nazwę pliku `.db` pasującą do pliku `.pcap` (ale możesz ją zmienić).
   - Po zakończeniu analizy możesz zabezpieczyć bazę hasłem w formacie ZIP.

## Przykładowy plik `.pcap`

Do repozytorium dołączono plik `sample.pcap` jako przykład.  
Możesz użyć go, by przetestować działanie aplikacji i zobaczyć, w jaki sposób skrypt filtruje i taguje pakiety.

## Uwagi

- Jeśli pojawiają się błędy związane z kompilacją, rozważ instalację narzędzi kompilacyjnych (np. Visual C++ Build Tools) lub użyj wersji biblioteki, która ma dostępne prekompilowane pakiety (*wheels*).
- Pamiętaj, że archiwum ZIP z hasłem AES (utworzone przez `pyzipper`) może nie być rozpoznawane przez bardzo stare programy do rozpakowywania, ale większość nowoczesnych narzędzi (7-Zip, WinRAR, WinZip) obsługuje to poprawnie.