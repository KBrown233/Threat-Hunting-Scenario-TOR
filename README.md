# Threat-Hunting-Scenario-TOR
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/KBrown233/Threat-Hunting-Scenario-TOR/blob/main/Threat-Hunting-Scenario-TOR-Event-Creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “kbuser” downloaded a tor installer, did something that resulted in many tor-related files being copied top the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop. The events began at: 2025-04-06T17:25:05.0700347Z.

**Query used to locate events:**

```kql
let target_machine = "windows-mde-kb";
DeviceFileEvents
| where DeviceName == target_machine
| where FileName contains "tor"
| where Timestamp >= datetime(2025-04-06T17:25:05.0700347Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account= InitiatingProcessAccountName

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/71402e84-8767-44f8-908c-1805be31122d">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows”. Based on the logs returned, On April 6, 2025, at 10:26 AM, a user named "kbuser" on a Windows computer named "windows-mde-kb" launched a process. The process involved running a file named "tor-browser-windows-x86_64-portable-14.0.9.exe" located in the Downloads folder. This executable file was launched with a command to install it silently, without displaying any installation prompts or progress (as indicated by the "/S" command).

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "windows-mde-kb"
| where ProcessCommandLine startswith "tor-browser-windows"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “kbuser” actually opened the tor browser. There was evidence that they did open the browser at 2025-04-06T17:27:06.2706605Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterward. 

**Query used to locate events:**

```kql
 DeviceFileEvents
|where DeviceName == "windows-mde-kb"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeivceNetworkEvents table for any indication that the tor browser was used the establish a connection using any of the known ports. At 2025-04-06T17:27:47.3648532Z a user named "kbuser" on a Windows computer named "windows-mde-kb" successfully established a connection. The connection was made to the local address (127.0.0.1) on port 9150, and it was initiated by the "firefox.exe" process.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "windows-mde-kb"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

April 6, 2025 - 5:25:05 PM (UTC)
Event: File Download and Activity
Action: The user "kbuser" on a Windows computer "windows-mde-kb" downloaded a Tor installer.


Details: A search in the DeviceFileEvents table for any files related to "tor" revealed that several Tor-related files were copied to the desktop. Additionally, a file named "tor-shopping-list.txt" was created on the desktop.

### 2. Process Execution - TOR Browser Installation

April 6, 2025 - 10:26:00 AM (UTC)
Event: Tor Browser Installation
Action: "kbuser" launched the "tor-browser-windows-x86_64-portable-14.0.9.exe" file located in the Downloads folder.


Details: The file was executed with the "/S" command, indicating it was installed silently without user interaction or display of installation progress.

### 3. Process Execution - TOR Browser Launch

April 6, 2025 - 5:27:06 PM (UTC)
Event: Tor Browser Launch
Action: "kbuser" launched the Tor browser.


Details: Evidence from the DeviceFileEvents table indicated that firefox.exe (a Tor-related process) was triggered, followed by the spawning of tor.exe processes. This suggests that the user had successfully launched the Tor browser after its installation.

### 4. Network Connection - TOR Network

April 6, 2025 - 5:27:47 PM (UTC)
Event: Tor Network Connection Established
Action: "kbuser" established a successful connection to the Tor network.


Details: The firefox.exe process initiated a connection to the local IP address (127.0.0.1) on port 9150, which is commonly used by the Tor network for communication. This suggests that the Tor browser was functioning correctly and that the user was attempting to connect through the Tor network.


Connection Details:
Initiating Process: firefox.exe.
Remote IP: 127.0.0.1 (Localhost).
Port Used: 9150 (Tor-related port).

### 5. File Creation - TOR Shopping List

April 6, 2025 - 5:48:48 PM (UTC)
Event: File Creation - Tor Shopping List
Action: File creation detected
Details: The user “kbuser” created a file named tor-shopping-list.txt on the desktop, potentially indicating a list or notes related to their Tor browser activities. 
File Path: C:\Users\Kbuser\Desktop\tor-shopping-list.txt

---

## Summary

The series of events points to a user, kbuser, downloading, installing, and using the Tor browser on the device "windows-mde-kb". The actions began with the download of the installer and culminated in a successful connection to the Tor network, indicating that the user may have been attempting to browse the web anonymously or engage in activities typically associated with the Tor network, with possible documentation in the form of the “shopping list” file.

---

## Response Taken

TOR usage was confirmed on the endpoint windows-mde-kb by the user kbuser. The device was isolated and the user's direct manager was notified.

---
