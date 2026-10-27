#include <stdio.h>
#include <string.h>
#include <unistd.h> // EXCLUSIVELY for sleep() so my summary flows nicely
#include "security_event.h"

int loadEvents(const char *filename, SecurityEvent events[], int totalEvents){
    FILE *fptr = fopen(filename, "r");

    // If the file is empty / doesn't exist, exit gracefully
    if (fptr == NULL){
        printf("The file failed to open.\n");
        return -1;
    } 

    int i = 0; // Counter 

    // while each line has 4 whitespace-separated values
    while (i < MAX_EVENTS && fscanf(fptr, "%24s %15s %9s %d", 
                events[i].eventType, events[i].eventSource,
                events[i].accountName, &events[i].severity) == 4) {
        i++;
    }
    printf("From %s: %d event(s) loaded!\n",filename, i);
    fclose(fptr);
    return i; // returns the total number of events loaded for use in main.c
}

// Expects pre-validated input, run loadEvents() first.
void displayEvent(int i, SecurityEvent events[]){
    i -= 1; // Lowers number provided by one to account for 0th index
    printf("%d. %s\n"
                "   IP Address: %s\n"
                "   Username: %s\n"
                "   Severity: %d\n\n", 
            i+1, events[i].eventType, events[i].eventSource,
            events[i].accountName, events[i].severity);
 }

void displayEvents(SecurityEvent events[], int totalEvents){
    for (int i = 0; i < totalEvents; i++){
        printf("%d. %s\n"
                    "   IP Address: %s\n"
                    "   Username: %s\n"
                    "   Severity: %d\n\n", 
                i+1, events[i].eventType, events[i].eventSource,
                events[i].accountName, events[i].severity);
    }
}

int countEventsByType(SecurityEvent events[], int totalEvents, const char *eventType) {
    int count = 0;
    for (int i = 0; i < totalEvents; i++){
        // If the event strings are identical
        if (strcmp(events[i].eventType, eventType) == 0){
            count++;
        }
    }
    return count;
}

int countFailedLogins(SecurityEvent events[], int totalEvents){
    return countEventsByType(events, totalEvents, "FAILED_LOGIN");
}

int countPortScanEvents(SecurityEvent events[], int totalEvents){
    return countEventsByType(events, totalEvents, "PORT_SCAN");  
}

int countUAEvents(SecurityEvent events[], int totalEvents){
    return countEventsByType(events, totalEvents, "UNAUTHORIZED_ACCESS");  
}

int countMalwareEvents(SecurityEvent events[], int totalEvents){
    return countEventsByType(events, totalEvents, "MALWARE");  
}

int countPhishingEvents(SecurityEvent events[], int totalEvents){
    return countEventsByType(events, totalEvents, "PHISHING");  
}

int countCriticalEvents(SecurityEvent events[], int totalEvents){
    int critical = 0;
    for (int i = 0; i < totalEvents; i++){
        // Counts every event with a severity greater than or equal to 9
        if (events[i].severity >= CRITICAL_THRESHOLD){
            critical++;
        }
    }
    return critical;  
}


int findHighestSeverity(SecurityEvent events[], int totalEvents){
    int highest = 0;
    for (int i = 0; i < totalEvents; i++){
        if (events[i].severity > highest){
            highest = events[i].severity;
        }
    }
    return highest;  
}

int countHighestSeverity(SecurityEvent events[], int totalEvents){
    int count = 0;
    int highest = findHighestSeverity(events, totalEvents);

    for (int i = 0; i < totalEvents; i++){
        if (events[i].severity == highest){
            count++;
        }
    }
    return count;
}


void displaySummary(SecurityEvent events[], int totalEvents){
    uSleep(1);
    printf("=================\n");
    printf("     Summary     \n");
    printf("=================\n\n");
    uSleep(2);

    printf("Displaying events 3, 9, and 27...\n\n");
    uSleep(1);
    displayEvent(3, events);
    displayEvent(9, events);
    displayEvent(27, events);
    uSleep(2);

    printf("Displaying all %d events...\n\n", totalEvents);
    uSleep(2);
    displayEvents(events, totalEvents);
    uSleep(2);

    printf("Generating metrics...\n\n");
    uSleep(2);

    printf("Failed login attempts found: %d\n", countFailedLogins(events, totalEvents));
    printf("Port scan events found: %d\n", countPortScanEvents(events, totalEvents));
    printf("Unauthorized access events found: %d\n", countUAEvents(events, totalEvents));
    printf("Malware events found: %d\n", countMalwareEvents(events, totalEvents));
    printf("Phishing events found: %d\n\n", countPhishingEvents(events, totalEvents));

    uSleep(1);
    printf("Number of critical events: %d\n", countCriticalEvents(events, totalEvents));
    printf("Highest severity event: %d (%d other events share this severity level)\n", findHighestSeverity(events, totalEvents), countHighestSeverity(events, totalEvents) - 1);
}