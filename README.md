# Praxisprojekt-ss-2023-AdrianBertram
Github des Praxisprojekts von Adrian Bertram im Sommersemester 2023

# Dokumentation
## 1. Einleitung
Im Rahmen dieses Praxisprojekts soll die IT-Sicherheit verbessert werden, indem verschiedene Hack-Angriffe auf eine virtuelle Maschine (VM) durchgeführt werden. 
Dabei soll der Fokus auf Client-Login Services gelegt werden, da dieser ein zentraler Angriffspunkt für potenzielle Angreifer darstellt. 
Ziel ist es, Schwachstellen in der Sicherheitsarchitektur der VM zu finden und zu beheben, sowie eine branchen-gemäße Sicherheitsrichtlinie für Passwörter eines Unternehmens basierend auf den Ergebnissen zu verfassen. 

Durch dieses Projekt werden mir Informationssicherheitstechnische Komponenten in der echten Welt durch die Nachstellung eines realen Szenarios und dem Aufsetzen einer Informationssicherheitsrichtlinie vermittelt. 
Außerdem werden mir wichtige Skills wie das Aufsetzen einer Virtual Machine und dem Installieren von Services, welches unerlässlich ist, wenn man eine Karriere in IT-Security anstrebt, näher gebracht.
Wenn man im Bereich der IT-Sicherheit arbeiten möchte, ist es wichtig, über Kenntnisse und Fähigkeiten im Bereich Hacking zu verfügen. 
Hierbei geht es jedoch nicht darum, illegale Aktivitäten durchzuführen oder Schaden anzurichten, sondern vielmehr darum, die Perspektive eines potenziellen Angreifers einzunehmen, um Schwachstellen in Systemen zu erkennen und zu beheben.

## 2. Einordnung 

### 2.1 Rechtlicher Rahmen 
<p> In Deutschland gibt es keinen spezifischen rechtlichen Rahmen, der sich ausschließlich auf das Aufsetzen einer virtuellen Maschine im eigenen lokalen Netzwerk bezieht. 
Das Einrichten und Verwenden einer virtuellen Maschine in Ihrem eigenen Heimnetzwerk ist grundsätzlich legal, solange Sie die geltenden Gesetze und Bestimmungen einhalten.
Es gibt jedoch einige rechtliche Aspekte und allgemeine Richtlinien, die berücksichtigt werden sollten: <br>
  
- Es ist wichtig sicherzustellen, dass gültige Lizenzen für die verwendeten Betriebssysteme und Anwendungen in der virtuellen Maschine vorhanden sind.
  
- Wenn personenbezogene Daten in der virtuellen Maschine verarbeitet werden, müssen die geltenden Datenschutzbestimmungen, insbesondere die EU-Datenschutz-Grundverordnung (DSGVO), eingehalten werden. 
Angemessene Sicherheitsmaßnahmen sollten ergriffen werden, um den Schutz und die Vertraulichkeit der Daten zu gewährleisten.

- Es ist sehr wichtig, die Sicherheit der virtuellen Maschine und des lokalen Netzwerks zu gewährleisten, um unautorisierten Zugriff oder Sicherheitsverletzungen zu verhindern.
  
### 2.2 Inhaltlicher Rahmen 

- In diesem Projekt ist zu beachten, dass die Sicherheitsrichtlinien nur begrenzt berücksichtigt werden können, da es sich um einen Selbsttest handelt. 
  Es wird davon ausgegangen, dass Sie jederzeit Zugriff auf alle Passwörter haben, was in realen Umständen nicht der Fall wäre.

- Obwohl dieser Selbsttest keine vollständige Umsetzung dieser Sicherheitsmaßnahmen erfordert, ist es dennoch wichtig, sich der Bedeutung dieser Praktiken bewusst zu sein und sie in realen Szenarien angemessen umzusetzen. 
  
  
  

## 3. Setup
  
<p> Das initiale Setup besteht aus einer virtuellen Maschine, welche mit Virtualbox konfiguriert wurde. Dazu musste ein Remote-Access eingerichtet werden.
Auf diesen wird dann von einem anderen Computer aus dem Netzwerk zugegriffen. <p>
  
## 4. Vorgehensweise
Zunächst wird eine VM(Virtual Machine) mit einem Client-Login Service eingerichtet.
Für diesen Zweck verwende ich VirtualBox um die VM mit dem Ubuntu Betriebssystem einzurichten.

Die weiteren Schritte sind aktuell(Subject to Change):
  
1. Simulieren der Werksteinstellungen eines neu aufgesetzten Gerätes(Account:admin Pw: admin) 
  
2. eine veraltete Version von Telnet(veralteter Remote Acess Service) zu installieren und dort iterativ die Sicherheitslücken zu brechen und aufzuweisen.
  
3. eine neue Version von SSL(Industriestandart für Remote Acess) zu installieren und dort iterativ die Sicherheitslücken zu brechen und aufzuweisen. 
  
4. Im Zuge dessen das zu brechende Passwort iterativ zu ändern, bis dieses einen branchenüblichen Sicherheitsstandart aufweist. 
  
5. Ausarbeitung der Social-Engineering Sicherheitslücken bei fehlendem Verständnis der fiktiven Mitarbeiter der Firma zur Prävention von Social Engineering
  
6. Auswertung von anderen Sicherheitsmaßnahmen: SSH Key Encryption und 2FA


 
### 4.1 Social Engineering
<p> Social Engineering bezieht sich auf eine Form der Manipulation, bei der Menschen getäuscht oder überlistet werden, um vertrauliche Informationen preiszugeben, Zugang zu Systemen zu gewähren oder bestimmte Handlungen auszuführen, die ihnen normalerweise nicht zustehen würden. 
Es nutzt psychologische Tricks und soziale Interaktionen, um das Vertrauen von Personen zu gewinnen und diese dazu zu bringen, ungewollte Handlungen durchzuführen. <br>
<p> Indem der Angreifer geschickt soziale Manipulationstechniken einsetzt, gelingt es ihm, den Mitarbeiter zu überzeugen, ihm den Fernzugriff auf den Computer zu ermöglichen oder sogar Benutzernamen und Passwörter preiszugeben. 
Sobald der Angreifer Zugriff hat, kann er vertrauliche Daten stehlen, Malware installieren oder das System anderweitig kompromittieren. <br>
<p> Social Engineering umgeht effektiv viele komplexe IT-Sicherheitssysteme, einschließlich Firewalls und Passwörter, und stellt daher eine besonders gefährliche Bedrohung dar.
Indem der Angreifer geschickt soziale Manipulationstechniken einsetzt, gelingt es ihm, den Mitarbeiter zu überzeugen, ihm den Fernzugriff auf den Computer zu ermöglichen oder sogar Benutzernamen und Passwörter preiszugeben. <br>
<p> Beispiel: Person X arbeitet in einem Unternehmen. Ihr Profil ist auf Linkedin mit Klarnamen öffensichtlich einsehbar, inklusive aktuellem Arbeitsplatz. Da viele Unternehmen die gleiche Domain für E-Mail-Adressen benutzen (vorname.nachname@Firmenname.com)
lässt sich so mit hoher Wahrscheinlichkeit ihre E-Mail Adresse ermitteln. Person X ist außerdem bei Facebook, wo sie Fotos ihrer Katzen inklusive ihrer Namen öffentlich für jeden einsehbar teilt. 
Ein Hacker könnte so ihre Liebe zu ihren Katzen ausnutzen, indem er eine Email verfasst, wo er in den Titel schreibt: "Ihre Katzen namens x und y sind verletzt". <br>
Dies führt zu einem Vertrauensvorschuss von Person X, da der Hacker ja ihre Katzennamen kennt. Sie klickt auf die E-Mail und auf den darin enthaltenden Link, wo der Hacker behauptet sie könnte sich bei ihm melden um zu wissen was los ist. <p>  
Unbekannte Links können zu infizierten Websites führen, die Malware oder Viren enthalten. Wenn Sie auf solche Links klicken, besteht die Gefahr, dass Ihr Computer oder Ihre persönlichen Daten infiziert werden.
Unbekannte Links können Teil von Phishing-Angriffen sein, bei denen Betrüger gefälschte Websites erstellen, die denen von legitimen Unternehmen ähneln. 
Wenn Sie auf solche Links klicken und persönliche sensible Informationen eingeben, könnten diese von den Angreifern gestohlen und für betrügerische Zwecke verwendet werden. <br>

  ### 4.2 Sniffing
### 4.3 Brute Force
### 4.4 Word List
  
## 5. SSH Key Encryption
  
## 6. Hashing
<p> Es ist wichtig zu beachten, dass die Sicherheit von Hash-Funktionen im Laufe der Zeit verändert werden kann, da neue Schwachstellen entdeckt werden. Daher ist es ratsam, sich über die aktuellsten Empfehlungen und bewährten Verfahren in Bezug auf Hash-Funktionen auf dem Laufenden zu halten. <br>
  
MD5 (Message Digest Algorithm 5): 
<p> MD5 ist eine häufig verwendete Hash-Funktion, die eine 128-Bit-Prüfsumme für eine Eingabe erzeugt. Es ist jedoch wichtig zu beachten, dass MD5 als unsicher gilt und nicht für kryptografische Zwecke verwendet werden sollte. <br>

SHA-1 (Secure Hash Algorithm 1): 
<p> 
SHA-1 ist eine Hash-Funktion, die eine 160-Bit-Prüfsumme erzeugt. Ähnlich wie MD5 gilt auch SHA-1 als unsicher und sollte nicht für kryptografische Anwendungen verwendet werden. <br>

SHA-256 (Secure Hash Algorithm 256-bit): 
<p> SHA-256 ist Teil der SHA-2-Familie von Hash-Funktionen und erzeugt eine 256-Bit-Prüfsumme. Es wird weithin für kryptografische Anwendungen verwendet, wie zum Beispiel zur Sicherung von Passwörtern und zur Integritätsprüfung von Daten. <br>

SHA-3 (Secure Hash Algorithm 3): 
<p> SHA-3 ist eine weitere Familie von Hash-Funktionen und wurde als Alternative zu den SHA-2-Algorithmen entwickelt. Es bietet verschiedene Varianten mit unterschiedlichen Ausgabegrößen, einschließlich SHA-3-256 und SHA-3-512. <br>

bcrypt: 
<p> bcrypt ist ein Passwort-Hashing-Algorithmus, der speziell für die sichere Speicherung von Passwörtern entwickelt wurde. Er verwendet eine Kombination aus Adaptivem Hashing und Salzen, um Passwörter zu schützen. bcrypt ist aufgrund seines langsamen Algorithmus gegen Brute-Force-Angriffe resistent. <br>

  
## Sicherheit: 
<p> In einer zunehmend digitalen Welt ist die Sicherheit von Informationen und Daten von größter Bedeutung. Hashing-Methoden spielen eine wichtige Rolle bei der Sicherung von Passwörtern, der Integritätsprüfung von Daten und anderen kryptografischen Anwendungen. Durch das Verständnis der verschiedenen Hashing-Methoden können Entwickler sicherstellen, dass sie die sichersten Optionen wählen, um die Vertraulichkeit und Integrität der Daten zu gewährleisten. <br>

## Schwachstellen erkennen: 
<p> Indem man sich mit den verschiedenen Hashing-Methoden vertraut macht, wird man auch über mögliche Schwachstellen und Sicherheitsrisiken informiert. Wie bereits erwähnt, gelten MD5 und SHA-1 als unsicher und sollten vermieden werden. Durch Kenntnis der Schwachstellen kann man verhindern, dass veraltete und anfällige Hashing-Algorithmen in eigenen Anwendungen verwendet werden. <br>

## Kompatibilität: 
<p> In einigen Fällen ist es notwendig, mit bestehenden Systemen und Datenbanken zu arbeiten, die bereits bestimmte Hashing-Methoden verwenden. Indem man sich mit den verschiedenen Methoden vertraut macht, kann man die Kompatibilität gewährleisten und gegebenenfalls Konvertierungen oder Aktualisierungen durchführen, um die Sicherheit zu verbessern. <br>

## Performance und Effizienz: 
<p> Jede Hashing-Methode hat ihre eigenen Eigenschaften in Bezug auf Geschwindigkeit und Effizienz. Je nach den Anforderungen der Anwendung kann es wichtig sein, eine Hashing-Methode zu wählen, die die gewünschte Leistung bietet. Durch das Verständnis der Stärken und Schwächen der einzelnen Methoden kann man die richtige Wahl treffen und eine optimale Leistung erzielen. <br>

## Aktuelle Entwicklungen: 
<p> Die Welt der kryptografischen Algorithmen und Sicherheit entwickelt sich ständig weiter. Neue Hashing-Methoden werden entwickelt, um den steigenden Sicherheitsanforderungen gerecht zu werden. Durch das Auseinandersetzen mit den fünf genannten Methoden kann man ein grundlegendes Verständnis für Hashing-Verfahren entwickeln und sich auf dem Laufenden halten, um zukünftige Entwicklungen zu verstehen und entsprechend reagieren zu können. <br>
  
  
  
## 7. 2FA

## 8. Ziel
<p> Das erste Ziel dieses Projekts ist es, die IT-Sicherheit einer VM zu verbessern, indem verschiedene Hack-Angriffe auf den Client-Login Service durchgeführt werden. 
Dabei sollen Schwachstellen gefunden, beschrieben und behoben werden. Dieser Ablauf soll mehrmals wiederholt werden, um die Wirksamkeit der durchgeführten Maßnahmen zu überprüfen. <br>

<p> Das zweite Ziel ist das vertraut machen mit gängigen Sicherheitsmaßnahmen und dem anschließenden Vergleich von verschiedenen anwendbaren Methoden. <br>

<p> Das dritte Ziel ist, eine branchen-gemäße Passwortsicherheitsrichtlinie zu formulieren, welche alle festgestellten Gefahren präventiv verhindern oder massiv erschweren soll. In dieser Richtlinie sollen außerdem nach einem ausführlichen Vergleich der vorher aufgeführten Sicherheitsmaßnahmen die für den jeweiligen Kontext die für den Gebrauch genannt werden, die dem Anwendungszweck und Kontext am besten entspricht. <br>

## 9. Auswertung
### 9.1 Daten
### 9.2 Anaylse der Daten
