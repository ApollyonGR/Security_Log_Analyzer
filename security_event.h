#ifndef SECURITY_EVENT_H
#define SECURITY_EVENT_H

#define MAX_EVENTS 50
#define MAX_EVENT_LENGTH 25
#define MAX_USERNAME_LENGTH 10
#define MAX_IP_ADDRESS_LENGTH 16
#define CRITICAL_THRESHOLD 9
#define LOG_RELATIVE_FILEPATH "security.log"

typedef struct {
    char eventType[MAX_EVENT_LENGTH];
    char eventSource[MAX_IP_ADDRESS_LENGTH];
    char accountName[MAX_USERNAME_LENGTH];
    int severity;
} SecurityEvent;

// Passing the events[] struct array for each function prevents extern usage
// Also just good practice from what I read online
int loadEvents(const char *filename, SecurityEvent events[], int totalEvents);

void displayEvent(int i, SecurityEvent events[]);
void displayEvents(SecurityEvent events[], int totalEvents);

int countEventsByType(SecurityEvent events[], int totalEvents, const char *eventType);

int countFailedLogins(SecurityEvent events[], int totalEvents);
int countPortScanEvents(SecurityEvent events[], int totalEvents);
int countUAEvents(SecurityEvent events[], int totalEvents);
int countMalwareEvents(SecurityEvent events[], int totalEvents);
int countPhishingEvents(SecurityEvent events[], int totalEvents);
int countCriticalEvents(SecurityEvent events[], int totalEvents);
int findHighestSeverity(SecurityEvent events[], int totalEvents);
int countHighestSeverity(SecurityEvent events[], int totalEvents);

// Creates a universal sleep command depending on which operating system you compile the program in
#ifdef _WIN32
    #include <windows.h>
    #define uSleep(seconds) Sleep((DWORD)((seconds) * 1000))
#else
    #include <unistd.h>
    #define uSleep(seconds) sleep(seconds)
#endif

void displaySummary(SecurityEvent events[], int totalEvents);

#endif 