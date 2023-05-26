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
  
## 5. Probleme

## 6. Ziel
<p> Das erste Ziel dieses Projekts ist es, die IT-Sicherheit einer VM zu verbessern, indem verschiedene Hack-Angriffe auf den Client-Login Service durchgeführt werden. 
Dabei sollen Schwachstellen gefunden, beschrieben und behoben werden. Dieser Ablauf soll mehrmals wiederholt werden, um die Wirksamkeit der durchgeführten Maßnahmen zu überprüfen. <br>

<p> Das zweite Ziel ist, eine branchen-gemäße Passwortsicherheitsrichtlinie zu formulieren, welche alle festgestellten Gefahren präventiv verhindern oder massiv erschweren soll. <br>

## 7. Auswertung
### 7.1 Daten
### 7.2 Anaylse der Daten
