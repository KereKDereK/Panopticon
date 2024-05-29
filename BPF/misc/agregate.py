import sqlite3
import sys
import os

syscall_groups = {
    'file_operations': [0, 1, 2, 3, 85, 257, 303, 304, 319, 133, 259, 82, 264, 316, 76, 77, 285, 83, 258, 84, 79, 80, 81, 161, 78, 217, 212, 86,
                        265, 88, 266, 87, 263, 89, 267, 95, 4, 6, 5, 262, 90, 91, 268, 92, 94, 93, 260, 132, 235, 261, 280, 21, 269,
                        188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 16, 72, 32, 33, 292, 73, 19, 17, 295, 20, 18, 296,
                        8, 40, 75, 74, 26, 277, 162, 306, 206, 207, 209, 208, 210, 23, 270, 7, 271, 213, 291, 233, 232, 281],
    'process_management': [56, 57, 58, 59, 322, 60, 231, 61, 247, 39, 110, 186, 112, 124, 109, 121, 111, 105, 102, 106, 104, 117, 118,
                           119, 120, 113, 114, 122, 123, 107, 108, 116, 115, 308, 160, 97, 302, 98, 314, 315, 144, 145, 142, 143, 203,
                           204, 146, 147, 148, 24, 141, 140, 251, 252, 12, 9, 11, 25, 10, 28, 149, 325, 151, 150, 152, 27, 324, 154,
                           126, 125, 205, 211, 218, 158, 134, 157, 317, 101, 310, 311, 312, 272], 
    'network_operations': [41, 53, 54, 55, 51, 52, 49, 50, 43, 288, 42, 48, 45, 47, 299, 44, 46, 307, 170, 171, 321],
}

def process_results(session_id):
    conn = sqlite3.connect('../filters/panopticon.db')
    cursor = conn.cursor()

    query = f"""
    SELECT SESSION_ID, GROUP_CONCAT(SYSCALL_ID)
    FROM SYSCALL_EVENTS
    WHERE SESSION_ID = {session_id}
    GROUP BY SESSION_ID;
    """

    cursor.execute(query)
    results = cursor.fetchall()

    for row in results:
        key, syscall_numbers = row
        syscall_numbers = [int(num) for num in syscall_numbers.split(',')]

        grouped_syscalls = {}
        for group_name, group_syscalls in syscall_groups.items():
            grouped_syscalls[group_name] = [num for num in syscall_numbers if num in group_syscalls]

        print(f"Session id: {key}")
        for group_name, group_syscalls in grouped_syscalls.items():
            print(f"   {group_name} number of syscalls: {len(group_syscalls)}")

    conn.close()

def verbose_results():
    conn = sqlite3.connect('../filters/panopticon.db')
    cursor = conn.cursor()

    query = f"""
    SELECT SESSION_ID, SYSCALL_ID, SYSCALL_TIMESTAMP, SYSCALL_STACKTRACE
    FROM SYSCALL_EVENTS
    WHERE SESSION_ID = {session_id}
    """

    cursor.execute(query)
    results = cursor.fetchall()

    print("\tID\t\tTIMESTAMP\t\tSTACKTRACE")
    for row in results:
        fake_id, id, tstmp, stacktrace = row
        print(f"\t{id}\t\t{tstmp}\t\t")
        for line in stacktrace.splitlines():
            print(f"\t\t\t\t\t\t{line}")

def network_results(session_id):
    conn = sqlite3.connect('../filters/panopticon.db')
    cursor = conn.cursor()

    query = f"""
    SELECT DISTINCT SESSION_ID, DST_IP
    FROM NETWORK_EVENTS
    WHERE SESSION_ID = {session_id}
    GROUP BY SESSION_ID;
    """

    cursor.execute(query)
    results = cursor.fetchall()

    for row in results:
        id, unique_ips = row
        unique_ips = unique_ips.split(',')
        print("Unique destination IP addresses:")
        for ip in unique_ips:
            print(f"- {ip}")
        print()

    conn.close()

def callgrind_results():
    conn = sqlite3.connect('../filters/panopticon.db')
    cursor = conn.cursor()

    query = f"""
    SELECT SESSION_ID, SYMBOL_NAME, EVENT_TIMESTAMP
    FROM CALLGRIND_EVENTS
    WHERE SESSION_ID = {session_id}
    """

    cursor.execute(query)
    results = cursor.fetchall()

    print("\SYMBOL NAME\t\tTIMESTAMP")
    for row in results:
        id, sname, timestamp = row
        print(f"\t{sname}\t\t\t\t\t{timestamp}")

if len(sys.argv) < 2:
    print("Usage: python3 agregate.py <SESSION_ID> [-v]")
    sys.exit(1)

session_id = sys.argv[1]
is_verbose = ""
if len(sys.argv) > 2:
    is_verbose = sys.argv[2]


os.system(f"./tshark_agregate.sh ../output/{session_id}/tcpdump.out.{session_id}.pcap")
process_results(session_id)
if (is_verbose == "-v"):
    verbose_results()
network_results(session_id)
callgrind_results()
os.system(f"kcachegrind ../output/{session_id}/callgrind.out.{session_id} > /dev/null 2>&1")

