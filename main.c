#include <stdio.h> 
#include "security_event.h"

int main(void){
    printf("\n" // Yes this is a dumb way to format it, no I do not care, it looks pretty :3
           "===================================\n"
           "  CYBR 310 Security Log Processor  \n" 
           "===================================\n"
           "\n"                                   );

    // Establishes struct array in main so it can be populated from loadEvents()
    SecurityEvent events[MAX_EVENTS];
    int total = loadEvents(LOG_RELATIVE_FILEPATH, events, MAX_EVENTS);
    
    // Runs loadEvents and stop the rest of the code if it fails 
    if (total < 0){
        printf("Failed to load events, exiting gracefully...\n");
        return -1;
    }
    
    printf("Displaying summary...\n\n");
    displaySummary(events, total);

    return 0;
}