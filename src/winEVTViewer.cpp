// Copyright 2007 Matthew A. Kucenski
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//#define _DEBUG_ 1

#include "libWinEVT/src/winEventFile.h"
#include "libpasswdFile/src/cygwinPasswdFile.h"
#include "libtimeUtils/src/timeZoneCalculator.h"
#include "libtimeUtils/src/timeUtils.h"

#include <popt.h>

#include <string>
#include <vector>
using namespace std;

#include "misc/stringType.h"
#include "misc/poptUtils.h"

#define UNDEFINED_STR						"Undefined"

#define ERROR_SEVERITY_SUCCESS_STR		"Success"
#define ERROR_SEVERITY_INFORMATION_STR	"Information"
#define ERROR_SEVERITY_WARNING_STR		"Warning"
#define ERROR_SEVERITY_ERROR_STR			"Error"

#define EVENTLOG_SUCCESS_STR				"Success"
#define EVENTLOG_ERROR_STR					"Error"
#define EVENTLOG_WARNING_STR				"Warning"
#define EVENTLOG_INFORMATION_STR			"Information"
#define EVENTLOG_AUDIT_SUCCESS_STR		"Success Audit"
#define EVENTLOG_AUDIT_FAILURE_STR		"Failure Audit"

typedef struct _PROGARGS {
	vector<string> filenameVector;

	bool bDelimited;
	bool bStringColumns;

	vector<int> eventVector;
	vector<int> eventIgnoreVector;

	vector<string> SIDVector;
	vector<string> SIDIgnoreVector;

	vector<string_t> sourceVector;
	vector<string_t> sourceIgnoreVector;

	vector<string_t> computerVector;
	vector<string_t> computerIgnoreVector;
	
	string strDateStart;
	string strDateEnd;
	
	int iTimeOffset;
	int iTimeDST;
	
	bool bWithFilename;
	bool bNoFilename;

	vector<int> recordVector;
	
	vector<string> typeVector;
	vector<string> typeIgnoreVector;
	
	bool bMactime;
} PROGARGS;

string getEventTypeString(unsigned short usEventType) {
	return (usEventType == EVENTLOG_SUCCESS ? EVENTLOG_SUCCESS_STR : 
				(usEventType == EVENTLOG_ERROR ? EVENTLOG_ERROR_STR : 
					(usEventType == EVENTLOG_WARNING ? EVENTLOG_WARNING_STR : 
						(usEventType == EVENTLOG_INFORMATION ? EVENTLOG_INFORMATION_STR : 
							(usEventType == EVENTLOG_AUDIT_SUCCESS ? EVENTLOG_AUDIT_SUCCESS_STR : 
								(usEventType == EVENTLOG_AUDIT_FAILURE ? EVENTLOG_AUDIT_FAILURE_STR : 
									UNDEFINED_STR))))));
}

string_t removeNewLines(string_t* pstr, string_t strRepl) {
	string_t strTmp;
	
	for (string_t::iterator it = pstr->begin(); it != pstr->end(); it++) {
		if (*it == STR('\n') || *it == STR('\r')) {
			while (*(it+1) == STR('\n') ||  *(it+1) == STR('\r')) {
				it++;
			}
			strTmp += strRepl;
		} else {
			strTmp += *it;
		}
	}
	
	return strTmp;
}

bool checkEventID(int iEvent, vector<int>* pEventVector, vector<int>* pEventIgnoreVector) {
	bool rv = true;

	if (pEventVector->size() > 0) {
		rv = false;
		for (vector<int>::iterator it = pEventVector->begin(); it != pEventVector->end(); it++) {
			if (iEvent == *it) {
				rv = true; 
				break;
			}
		}
	}	//if (pEventVector->size() > 0) {
	
	if (pEventIgnoreVector->size() > 0) {
		rv = true;
		for (vector<int>::iterator it = pEventIgnoreVector->begin(); it != pEventIgnoreVector->end(); it++) {
			if (iEvent == *it) {
				rv = false; 
				break;
			}
		}
	}	//if (pEventIgnoreVector->size() > 0) {
	
	return rv;	
}	//bool checkEventID(int iEvent, vector<int>* pEventVector) {

bool checkEventRecord(int iRecord, vector<int>* pRecordVector) {
	bool rv = true;

	if (pRecordVector->size() > 0) {
		rv = false;
		for (vector<int>::iterator it = pRecordVector->begin(); it != pRecordVector->end(); it++) {
			if (iRecord == *it) {
				rv = true; 
				break;
			}
		}
	}	//if (pRecordVector->size() > 0) {
	
	return rv;	
}	//bool checkRecordID(int iRecord, vector<int>* pRecordVector) {

bool checkEventSource(string_t strSource, vector<string_t>* pSourceVector, vector<string_t>* pSourceIgnoreVector) {
	bool rv = true;
	
	if (pSourceVector->size() > 0) {
		rv = false;
		for (vector<string_t>::iterator it = pSourceVector->begin(); it != pSourceVector->end(); it++) {
			if (strSource == *it) {
				rv = true;
				break;
			}
		}
	}	//if (pSourceVector->size() > 0) {
	
	if (pSourceIgnoreVector->size() > 0) {
		rv = true;
		for (vector<string_t>::iterator it = pSourceIgnoreVector->begin(); it != pSourceIgnoreVector->end(); it++) {
			if (strSource == *it) {
				rv = false;
				break;
			}
		}
	}	//if (pSourceIgnoreVector->size() > 0) {
	
	return rv;
}	//bool checkEventSource(string strSource, vector<string>* pSourceVector, vector<string>* pSourceIgnoreVector) {

bool checkEventComputer(string_t strComputer, vector<string_t>* pComputerVector, vector<string_t>* pComputerIgnoreVector) {
	bool rv = true;
	
	if (pComputerVector->size() > 0) {
		rv = false;
		for (vector<string_t>::iterator it = pComputerVector->begin(); it != pComputerVector->end(); it++) {
			if (strComputer == *it) {
				rv = true;
				break;
			}
		}
	}	//if (pComputerVector->size() > 0) {
	
	if (pComputerIgnoreVector->size() > 0) {
		rv = true;
		for (vector<string_t>::iterator it = pComputerIgnoreVector->begin(); it != pComputerIgnoreVector->end(); it++) {
			if (strComputer == *it) {
				rv = false;
				break;
			}
		}
	}	//if (pComputerIgnoreVector->size() > 0) {
	
	return rv;
}	//bool checkEventComputer(string strSource, vector<string>* pComputerVector, vector<string>* pComputerIgnoreVector) {

bool checkEventType(string strType, vector<string>* pTypeVector, vector<string>* pTypeIgnoreVector) {
	bool rv = true;
	
	if (pTypeVector->size() > 0) {
		rv = false;
		for (vector<string>::iterator it = pTypeVector->begin(); it != pTypeVector->end(); it++) {
			if (strType == *it) {
				rv = true;
				break;
			}
		}
	}	//if (pTypeVector->size() > 0) {
	
	if (pTypeIgnoreVector->size() > 0) {
		rv = true;
		for (vector<string>::iterator it = pTypeIgnoreVector->begin(); it != pTypeIgnoreVector->end(); it++) {
			if (strType == *it) {
				rv = false;
				break;
			}
		}
	}	//if (pTypeIgnoreVector->size() > 0) {
	
	return rv;
}	//bool checkEventType(string strType, vector<string>* pTypeVector, vector<string>* pTypeIgnoreVector) {

bool checkEventSID(string strSID, vector<string>* pSIDVector, vector<string>* pSIDIgnoreVector) {
	bool rv = true;
	
	if (pSIDVector->size() > 0) {
		rv = false;
		for (vector<string>::iterator it = pSIDVector->begin(); it != pSIDVector->end(); it++) {
			if (strSID == *it) {
				rv = true;
				break;
			}
		}
	}	//if (pSourceVector->size() > 0) {
	
	if (pSIDIgnoreVector->size() > 0) {
		rv = true;
		for (vector<string>::iterator it = pSIDIgnoreVector->begin(); it != pSIDIgnoreVector->end(); it++) {
			if (strSID == *it) {
				rv = false;
				break;
			}
		}
	}	//if (pSIDIgnoreVector->size() > 0) {
	
	return rv;
}	//bool checkEventSID(string strSID, vector<string>* pSIDVector, vector<string>* pSIDIgnoreVector) {

bool checkEventDate(unsigned long ulDateTime, string* pstrDateStart, string* pstrDateEnd) {
	bool rv = true;
	
	if (pstrDateStart->length() == 10) {
		struct tm* time = gmtime((time_t*)&ulDateTime);
		int iEventMonth = time->tm_mon + 1;
		int iEventDay = time->tm_mday;
		int iEventYear = time->tm_year + 1900;
	
		int iStartMonth = strtol(string(*pstrDateStart, 0, 2).c_str(), NULL, 10);
		int iStartDay = strtol(string(*pstrDateStart, 3, 2).c_str(), NULL, 10);
		int iStartYear = strtol(string(*pstrDateStart, 6, 4).c_str(), NULL, 10);
		
		if (iEventYear < iStartYear) {
			rv = false;
		} else if (iEventYear == iStartYear) {
			if (iEventMonth < iStartMonth) {
				rv = false;
			} else if (iEventMonth == iStartMonth) {
				if (iEventDay < iStartDay) {
					rv = false;
				}
			}
		}
	}
	
	if (pstrDateEnd->length() == 10) {
		struct tm* time = gmtime((time_t*)&ulDateTime);
		int iEventMonth = time->tm_mon + 1;
		int iEventDay = time->tm_mday;
		int iEventYear = time->tm_year + 1900;

		int iEndMonth = strtol(string(*pstrDateEnd, 0, 2).c_str(), NULL, 10);
		int iEndDay = strtol(string(*pstrDateEnd, 3, 2).c_str(), NULL, 10);
		int iEndYear = strtol(string(*pstrDateEnd, 6, 4).c_str(), NULL, 10);
		
		if (iEventYear > iEndYear) {
			rv = false;
		} else if (iEventYear == iEndYear) {
			if (iEventMonth > iEndMonth) {
				rv = false;
			} else if (iEventMonth == iEndMonth) {
				if (iEventDay > iEndDay) {
					rv = false;
				}
			}
		}
	}
	
	return rv;
}	//bool checkEventDate(unsigned long ulDateTime, string* pstrDateStart, string* pstrDateEnd) {

bool displayEvent(winEvent* pEvent, PROGARGS* args) {
	bool rv = true;

	if (!checkEventSID(pEvent->getSIDString(), &args->SIDVector, &args->SIDIgnoreVector) ||
		!checkEventSource(pEvent->getSourceName(), &args->sourceVector, &args->sourceIgnoreVector) ||
		!checkEventComputer(pEvent->getComputerName(), &args->computerVector, &args->computerIgnoreVector) ||
		!checkEventID(pEvent->getEventCode(), &args->eventVector, &args->eventIgnoreVector) ||
		!checkEventDate(pEvent->getTimeGenerated(), &args->strDateStart, &args->strDateEnd) ||
		!checkEventRecord(pEvent->getRecordNumber(), &args->recordVector) ||
		!checkEventType(getEventTypeString(pEvent->getEventType()), &args->typeVector, &args->typeIgnoreVector)
	) {
		rv = false;
	}
	
	return rv;
}	//bool displayEvent(winEvent* pEvent, PROGARGS args) {

int main(int argc, const char** argv) {
	int rv = EXIT_FAILURE;
	
	PROGARGS arguments;
	arguments.bDelimited = false;
	arguments.bStringColumns = false;
	arguments.iTimeOffset = 0;
	arguments.iTimeDST = 0;
	arguments.bWithFilename = false;
	arguments.bNoFilename = false;
	arguments.bMactime = false;
	
	cygwinPasswdFile pwdFile;
	bool matchSIDtoUsernames = false;

	timeZoneCalculator tzcalc;

	//TODO Add an option to retrieve a the record that wraps around a 
	//	particular file offset.  e.g., If I grep the .Evt file for 
	//	an ip address and get a file offset, I should be able to 
	//	plug the offset back into winEventViewer and have it return 
	//	the complete event record that contains that IP address.
	
	//TODO Time Skew

	struct poptOption optionsTable[] = {
		{"delimited", 		'd',	POPT_ARG_NONE,		NULL,	20,		"Display in comma-delimited format.", NULL},
		{"strings", 			't',	POPT_ARG_NONE,		NULL,	50,		"Display strings as additional columns. Only applicable with --delimited.", NULL},
		{"computer", 		'c',	POPT_ARG_STRING,	NULL,	10,		"Only display events from the specified computer. May be specified more than once.", "name"},
		{"computer-ignore",	 0,		POPT_ARG_STRING,	NULL,	15,		"Ignore the specified computer. May be specified more than once.", "name"},
		{"event", 			'e',	POPT_ARG_INT,		NULL,	30,		"Only display specified event. May be specified more than once.", "eventID"},
		{"event-ignore", 	 0,		POPT_ARG_INT,		NULL,	35, 	"Ignore the specified event. May be specified more than once.", "eventID"},
		{"source", 			's',	POPT_ARG_STRING,	NULL,	40, 	"Only display events from the specified source. May be specified more than once.", "name"},
		{"source-ignore", 	 0,		POPT_ARG_STRING,	NULL,	45, 	"Ignore the specified source. May be specified more than once.", "name"},
		{"sid", 				'u',	POPT_ARG_STRING,	NULL,	60, 	"Only display events from the specified SID. May be specified more than once.", "SID"},
		{"sid-ignore", 		 0,		POPT_ARG_STRING,	NULL,	65, 	"Ignore the specified SID. May be specified more than once.", "SID"},
		{"start-date", 		 0,		POPT_ARG_STRING,	NULL,	70, 	"Only display entries recorded after the specified date.", "mm/dd/yyyy"},
		{"end-date", 		 0,		POPT_ARG_STRING,	NULL,	80, 	"Only display entries recorded before the specified date.", "mm/dd/yyyy"},
		{"with-filename",	'H',	POPT_ARG_NONE,		NULL,	110, 	"Display filename in output. Useful when batch processing multiple files.", NULL},
		{"no-filename", 	'h',	POPT_ARG_NONE,		NULL,	120, 	"Suppress filename in output.", NULL},
		{"record",			'r',	POPT_ARG_INT,		NULL,	130, 	"Only display specified record. May be specified more than once.", "recordNumber"},
		{"type",				 0,		POPT_ARG_STRING,	NULL,	140, 	"Only display events matching the specified type. May be specified more than once.", "name"},
		{"type-ignore",		 0,		POPT_ARG_STRING,	NULL,	145, 	"Ignore the specified type. May be specified more than once.", "name"},
		{"mactime",			'm', 	POPT_ARG_NONE, 		NULL,	150, 	"Display in the SleuthKit's mactime format."},
		{"passwd",			'p',	POPT_ARG_STRING,	NULL,	160, 	"Location of Cygwin passwd file (generated by mkpasswd -d) to use for SID to username conversions.", "filename"},
		{"timezone", 		'z',	POPT_ARG_STRING,	NULL,	170, 	"POSIX timezone string (e.g. 'EST-5EDT,M4.1.0,M10.1.0' or 'GMT-5') to be used when displaying data. Defaults to GMT.", "zone"},
		{"version",	 		0,		POPT_ARG_NONE,		NULL,	180,	"Display version.", NULL},
		POPT_AUTOHELP
		{NULL, 				 0, 	POPT_ARG_NONE, 		NULL, 0, 		NULL, NULL}
	};
	poptContext optCon = poptGetContext(NULL, argc, argv, optionsTable, 0);
	poptSetOtherOptionHelp(optCon, "[options] <filename> [<filename>] ...");
	
	if (argc < 2) {
		poptPrintUsage(optCon, stderr, 0);
		exit(EXIT_FAILURE);
	}

	string strTmp;
	int iOption = poptGetNextOpt(optCon);
	while (iOption >= 0) {
		switch (iOption) {
			case 10:
				strTmp = poptGetOptArg(optCon);
				arguments.computerVector.push_back(string_t(strTmp.begin(), strTmp.end()));
				break;

			case 15:
				strTmp = poptGetOptArg(optCon);
				arguments.computerIgnoreVector.push_back(string_t(strTmp.begin(), strTmp.end()));
				break;

			case 20:
				arguments.bDelimited = true;
				break;

			case 30:
				arguments.eventVector.push_back(strtol(poptGetOptArg(optCon), NULL, 10));
				break;

			case 35:
				arguments.eventIgnoreVector.push_back(strtol(poptGetOptArg(optCon), NULL, 10));
				break;

			case 40:
				strTmp = poptGetOptArg(optCon);
				arguments.sourceVector.push_back(string_t(strTmp.begin(), strTmp.end()));
				break;
			case 45:
				strTmp = poptGetOptArg(optCon);
				arguments.sourceIgnoreVector.push_back(string_t(strTmp.begin(), strTmp.end()));
				break;

			case 50:
				arguments.bStringColumns = true;
				break;

			case 60:
				strTmp = poptGetOptArg(optCon);
				arguments.SIDVector.push_back(string(strTmp.begin(), strTmp.end()));
				break;

			case 65:
				strTmp = poptGetOptArg(optCon);
				arguments.SIDIgnoreVector.push_back(string(strTmp.begin(), strTmp.end()));
				break;

			case 70:
				strTmp = poptGetOptArg(optCon);
				if (strTmp.length() == 10) {
					arguments.strDateStart = strTmp;
				} else {
					usage(optCon, "Invalid start date value", "e.g., mm/dd/yyyy");
					exit(EXIT_FAILURE);
				}
				break;

			case 80:
				strTmp = poptGetOptArg(optCon);
				if (strTmp.length() == 10) {
					arguments.strDateEnd = strTmp;
				} else {
					usage(optCon, "Invalid end date value", "e.g., mm/dd/yyyy");
					exit(EXIT_FAILURE);
				}
				break;

			case 90:
				arguments.iTimeOffset = strtol(poptGetOptArg(optCon), NULL, 10);
				break;

			case 110:
				arguments.bWithFilename = true;
				break;
				
			case 120:
				arguments.bNoFilename = true;
				break;

			case 130:
				arguments.recordVector.push_back(strtol(poptGetOptArg(optCon), NULL, 10));
				break;

			case 140:
				strTmp = poptGetOptArg(optCon);
				arguments.typeVector.push_back(string(strTmp.begin(), strTmp.end()));
				break;
			case 145:
				strTmp = poptGetOptArg(optCon);
				arguments.typeIgnoreVector.push_back(string(strTmp.begin(), strTmp.end()));
				break;
			
			case 150:
				arguments.bMactime = true;
				break;
			
			case 160:
				pwdFile.open(poptGetOptArg(optCon));
				matchSIDtoUsernames = true;
				break;
			case 170:
				if (tzcalc.setTimeZone(poptGetOptArg(optCon)) >= 0) {
				} else {
					usage(optCon, "Invalid time zone string", "e.g. 'EST-5EDT,M4.1.0,M10.1.0' or 'GMT-5'");
					exit(EXIT_FAILURE);
				}
				break;
			case 180:
				version(PACKAGE, VERSION);
				exit(EXIT_SUCCESS);
				break;
		}
		iOption = poptGetNextOpt(optCon);
	}
	
	if (iOption != -1) {
		usage(optCon, poptBadOption(optCon, POPT_BADOPTION_NOALIAS), poptStrerror(iOption));
		exit(EXIT_FAILURE);
	}
	
	const char* cstrFilename = poptGetArg(optCon);
	while (cstrFilename) {
		arguments.filenameVector.push_back(cstrFilename);
		cstrFilename = poptGetArg(optCon);
	}
	
	if (arguments.filenameVector.size() < 1) {
		usage(optCon, "You must specify at least one file", "e.g., events.evt");
		exit(EXIT_FAILURE);
	}
	
	if (arguments.bDelimited) {
		cout << "Time Zone: \"" << tzcalc.getTimeZoneString() << "\"" << endl;		//Display the timezone so that the reader knows which zone was used for this output
		if ((arguments.filenameVector.size() > 1 && arguments.bNoFilename == false) || arguments.bWithFilename == true) {
			printf("File,");
		}
		printf("Record,Offset,Type,Date,Time,Source,Category,Event,SID,Computer\n");
	}
	
	long lRecordCount = 0;
	for (vector<string>::iterator it = arguments.filenameVector.begin(); it != arguments.filenameVector.end(); it++) {
		winEventFile eventFile(*it);

		if (arguments.bMactime) {
			winEvent* pEvent = NULL;
			while (eventFile.getNextRecord(&pEvent) == WIN_EVENT_SUCCESS) {
				if (displayEvent(pEvent, &arguments) == true) {
					lRecordCount++;
					
					string strTimeWritten = getTimeString(tzcalc.calculateLocalTime(getFromUnix32(pEvent->getTimeWritten())));
					string strDateWritten = getDateString(tzcalc.calculateLocalTime(getFromUnix32(pEvent->getTimeWritten())));
					string strTimeGenerated = getTimeString(tzcalc.calculateLocalTime(getFromUnix32(pEvent->getTimeGenerated())));
					string strDateGenerated = getDateString(tzcalc.calculateLocalTime(getFromUnix32(pEvent->getTimeGenerated())));
			
#ifdef _NO_WIDE_STRING_SUPPORT_
					printf("EVT|%s|%lu|%lu||%s||%s|%s||%s||%lu|%lu||",
#else
					printf("EVT|%s|%lu|%lu||%ls||%s|%ls||%s||%lu|%lu||",
#endif
							it->c_str(),
							pEvent->getRecordNumber(),
							pEvent->getEventCode(),
							pEvent->getSourceName().c_str(),
							//pEvent->getSIDString().c_str(),
							(matchSIDtoUsernames ? pwdFile.getUsernameBySID(pEvent->getSIDString()).c_str() : pEvent->getSIDString().c_str()),
							pEvent->getComputerName().c_str(),
							getEventTypeString(pEvent->getEventType()).c_str(),
							pEvent->getTimeWritten(),
							pEvent->getTimeGenerated()
					);
					printf("\n");
				}	//if (displayEvent(pEvent, &arguments) == true) {
				delete pEvent;
				pEvent = NULL;
			}	//while (eventFile.getNextRecord(&pEvent) == WIN_EVENT_SUCCESS) {
		} else {	
			if (arguments.bDelimited) {
				winEvent* pEvent = NULL;
				while (eventFile.getNextRecord(&pEvent) == WIN_EVENT_SUCCESS) {
					if (displayEvent(pEvent, &arguments) == true) {
						lRecordCount++;

						string strTimeWritten = getTimeString(tzcalc.calculateLocalTime(getFromUnix32(pEvent->getTimeWritten())));
						string strDateWritten = getDateString(tzcalc.calculateLocalTime(getFromUnix32(pEvent->getTimeWritten())));
						string strTimeGenerated = getTimeString(tzcalc.calculateLocalTime(getFromUnix32(pEvent->getTimeGenerated())));
						string strDateGenerated = getDateString(tzcalc.calculateLocalTime(getFromUnix32(pEvent->getTimeGenerated())));

						if ((arguments.filenameVector.size() > 1 && arguments.bNoFilename == false) || arguments.bWithFilename == true) {
							printf("%s,", it->c_str());
						}
#ifdef _NO_WIDE_STRING_SUPPORT_
						printf("%lu,0x%lx,%s,%s,%s,%s,%d,%lu,%s,%s",
#else
						printf("%lu,0x%lx,%s,%s,%s,%ls,%d,%lu,%s,%ls",
#endif
								pEvent->getRecordNumber(),
								pEvent->getRecordOffset(),
								getEventTypeString(pEvent->getEventType()).c_str(),
								strDateGenerated.c_str(),//pEvent->getDateGeneratedString().c_str(),
								strTimeGenerated.c_str(),//pEvent->getTimeGeneratedString().c_str(),
								pEvent->getSourceName().c_str(),
								pEvent->getEventCategory(),
								pEvent->getEventCode(),
								//pEvent->getSIDString().c_str(),
								(matchSIDtoUsernames ? pwdFile.getUsernameBySID(pEvent->getSIDString()).c_str() : pEvent->getSIDString().c_str()),
								pEvent->getComputerName().c_str()
						);
						if (arguments.bStringColumns == true) {
							vector<string_t> vStrings;
							if (pEvent->getStrings(&vStrings) == WIN_EVENT_SUCCESS) {
								for (vector<string_t>::iterator it = vStrings.begin(); it != vStrings.end(); it++) {
#ifdef _NO_WIDE_STRING_SUPPORT_
									printf(",\"%s\"", removeNewLines(&(*it), STR(" _ ")).c_str());
#else
									printf(",\"%ls\"", removeNewLines(&(*it), STR(" _ ")).c_str());
#endif
								}
							}	//if (pEvent->getStrings(&vStrings) == WIN_EVENT_SUCCESS) {
						}	//if (arguments.bStringColumns == true) {
						printf("\n");
					}	//if (displayEvent(pEvent->getEventCode(), &arguments) == true) {
					
					delete pEvent;
					pEvent = NULL;
				}	//while (eventFile.getNextRecord(&pEvent) == WIN_EVENT_SUCCESS) {
			} else {	//if (bDelimited) {
				winEvent* pEvent = NULL;
				while (eventFile.getNextRecord(&pEvent) == WIN_EVENT_SUCCESS) {
					if (displayEvent(pEvent, &arguments) == true) {
						lRecordCount++;

						string strTimeWritten = getTimeString(tzcalc.calculateLocalTime(getFromUnix32(pEvent->getTimeWritten())));
						string strDateWritten = getDateString(tzcalc.calculateLocalTime(getFromUnix32(pEvent->getTimeWritten())));
						string strTimeGenerated = getTimeString(tzcalc.calculateLocalTime(getFromUnix32(pEvent->getTimeGenerated())));
						string strDateGenerated = getDateString(tzcalc.calculateLocalTime(getFromUnix32(pEvent->getTimeGenerated())));

						if ((arguments.filenameVector.size() > 1 && arguments.bNoFilename == false) || arguments.bWithFilename == true) {
							printf("%s ", it->c_str());
						}
#ifdef _NO_WIDE_STRING_SUPPORT_
						printf("%lu: (offset=0x%lx, length=0x%lx)\n\tDate Generated:\t\t%s\t\tSource:\t\t%s\n\tTime Generated (GMT):\t%s\t\tCategory:\t%u\n\tDate Written:\t\t%s\t\tEvent ID:\t%lu\n\tTime Written (GMT):\t%s\t\tUser:\t\t%s\n\tType:\t\t\t%-10s\t\tComputer:\t%s\n",
#else
						printf("%lu: (offset=0x%lx, length=0x%lx)\n\tDate Generated:\t\t%s\t\tSource:\t\t%ls\n\tTime Generated (GMT):\t%s\t\tCategory:\t%u\n\tDate Written:\t\t%s\t\tEvent ID:\t%lu\n\tTime Written (GMT):\t%s\t\tUser:\t\t%s\n\tType:\t\t\t%-10s\t\tComputer:\t%ls\n",
#endif
								pEvent->getRecordNumber(),
								pEvent->getRecordOffset(),
								pEvent->getRecordLength(),
								strDateGenerated.c_str(),//pEvent->getDateGeneratedString().c_str(),
								pEvent->getSourceName().c_str(),
								strTimeGenerated.c_str(),//pEvent->getTimeGeneratedString().c_str(),
								pEvent->getEventCategory(),
								strDateWritten.c_str(),//pEvent->getDateWrittenString().c_str(),
								pEvent->getEventCode(),
								strTimeWritten.c_str(),//pEvent->getTimeWrittenString().c_str(),
								//pEvent->getSIDString().c_str(),
								(matchSIDtoUsernames ? pwdFile.getUsernameBySID(pEvent->getSIDString()).c_str() : pEvent->getSIDString().c_str()),
								getEventTypeString(pEvent->getEventType()).c_str(),
								pEvent->getComputerName().c_str()
						);
			
						vector<string_t> vStrings;
						if (pEvent->getStrings(&vStrings) == WIN_EVENT_SUCCESS) {
							printf("\n\tStrings: (offset=0x%lx, count=%u)\n", pEvent->getStringsOffset(), pEvent->getNumStrings());
					
							int i=1;
							for (vector<string_t>::iterator it = vStrings.begin(); it != vStrings.end(); it++) {
#ifdef _NO_WIDE_STRING_SUPPORT_
								printf("\t%7d:\t%s\n", i++, removeNewLines(&(*it), STR(" _ ")).c_str());
#else
								printf("\t%7d:\t%ls\n", i++, removeNewLines(&(*it), STR(" _ ")).c_str());
#endif
							}
						}	//if (pEvent->getStrings(&vStrings) == WIN_EVENT_SUCCESS) {
						
						if (pEvent->getDataLength() > 0) {
							unsigned char* pData = NULL;
							if (pEvent->getData((char**)&pData) == WIN_EVENT_SUCCESS) {
								unsigned long ulDataLength = pEvent->getDataLength();
								printf("\n\tData: (offset=0x%lx, length=0x%lx)\n", pEvent->getDataOffset(), ulDataLength);
						
								unsigned long i,j;
								for (i=0; i<ulDataLength; ) {
									printf("\t   %04ld:\t", i);
									for (j=i; j<ulDataLength && j<i+8; j++) {
										printf("%s%02x", (j==i ? "" : " "), pData[j]);
									}
									for (; j<i+8; j++) {
										printf("   ");
									}
									printf("\t\t");
									for (j=i; j<ulDataLength && j<i+8; j++) {
										if (pData[j] == '\0') {
											printf(" .");
										} else if (pData[j] < 0x20 || pData[j] > 0x7e) {
											printf(" _");
										} else {
											printf(" %c", pData[j]);
										}
									}	//for (j=i; j<ulDataLength && j<i+8; j++) {
									for (; j<i+8; j++) {
										printf("  ");
									}
									printf("\n");
									i = j;
								}	//for (i=0; i<ulDataLength; ) {
								
								free(pData);
								pData = NULL;
							}	//if (pEvent->getData((char**)&pData) == WIN_EVENT_SUCCESS) {
						}	//if (pEvent->getDataLength() > 0) {
						
						printf("----------------------------------------------------------------------------------------------------\n");
					}	//if (displayEvent(pEvent->getEventCode(), &eventsVector) == true) {
					
					delete pEvent;
					pEvent = NULL;
				}	//while (eventFile.getNextRecord(&pEvent) == WIN_EVENT_SUCCESS) {
			}	//else {	//if (bDelimited) {
		}	//if (arguments.bMactime) {
	}	//for (vector<string>::iterator it = arguments.filenameVector.begin(); it != arguments.filenameVector.end(); it++) {
	printf("\nRecord Count: %ld\n", lRecordCount);
		
	exit(rv);	
}	//int main(int argc, const char** argv) {
