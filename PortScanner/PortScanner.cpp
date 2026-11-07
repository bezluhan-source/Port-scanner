// =====================================================================
//  PortScanner - a small multi-threaded TCP connect scanner in C++
//
//  FOR EDUCATIONAL AND AUTHORISED USE ONLY.
//  Only scan machines you own or have written permission to test.
//
//  Built for Windows (Winsock) in Visual Studio. It also compiles on
//  Linux/macOS (g++ -std=c++17 -pthread PortScanner.cpp -o portscanner).
// =====================================================================

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
using SocketHandle = SOCKET;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
using SocketHandle = int;
#define INVALID_SOCKET (-1)
#define closesocket close
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------
//  Settings the user can change from the command line
// ---------------------------------------------------------------------
struct Options
{
    std::string target = "";
    int  startPort = 1;
    int  endPort = 1024;
    int  timeoutMs = 500;   // how long to wait for each port
    int  threads = 100;   // how many ports we test at the same time
    bool skipConfirm = false; // --yes skips the permission question
    std::string outFile = "";    // optional file to save results to
};

// One result line: port number + its common service name
struct OpenPort
{
    int port;
    std::string service;
};

// ---------------------------------------------------------------------
//  Well-known ports, so we can say *what* is probably running there
// ---------------------------------------------------------------------
std::string ServiceName(int port)
{
    static const std::map<int, std::string> services = {
        {20, "FTP-data"}, {21, "FTP"}, {22, "SSH"}, {23, "Telnet"},
        {25, "SMTP"}, {53, "DNS"}, {67, "DHCP"}, {69, "TFTP"},
        {80, "HTTP"}, {110, "POP3"}, {111, "RPCbind"}, {123, "NTP"},
        {135, "MS-RPC"}, {137, "NetBIOS-NS"}, {139, "NetBIOS-SSN"},
        {143, "IMAP"}, {161, "SNMP"}, {389, "LDAP"}, {443, "HTTPS"},
        {445, "SMB"}, {465, "SMTPS"}, {587, "SMTP-Submit"}, {636, "LDAPS"},
        {993, "IMAPS"}, {995, "POP3S"}, {1433, "MSSQL"}, {1521, "Oracle"},
        {2049, "NFS"}, {3000, "Dev-server"}, {3306, "MySQL"},
        {3389, "RDP"}, {5432, "PostgreSQL"}, {5900, "VNC"},
        {5985, "WinRM"}, {6379, "Redis"}, {8000, "HTTP-alt"},
        {8080, "HTTP-proxy"}, {8443, "HTTPS-alt"}, {9200, "Elasticsearch"},
        {27017, "MongoDB"}
    };

    auto it = services.find(port);
    return it != services.end() ? it->second : "unknown";
}

// ---------------------------------------------------------------------
//  Networking helpers
// ---------------------------------------------------------------------

// Turn on the networking library (only needed on Windows)
bool StartNetworking()
{
#ifdef _WIN32
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
#else
    return true;
#endif
}

void StopNetworking()
{
#ifdef _WIN32
    WSACleanup();
#endif
}

// Turn a name like "localhost" or "192.168.1.10" into an IPv4 address
bool ResolveTarget(const std::string& host, sockaddr_in& out, std::string& ipText)
{
    addrinfo hints{};
    hints.ai_family = AF_INET;      // IPv4 only, to keep things simple
    hints.ai_socktype = SOCK_STREAM;  // TCP

    addrinfo* result = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 || result == nullptr)
        return false;

    out = *reinterpret_cast<sockaddr_in*>(result->ai_addr);
    freeaddrinfo(result);

    char buffer[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &out.sin_addr, buffer, sizeof(buffer));
    ipText = buffer;
    return true;
}

// Switch a socket between "blocking" (wait forever) and "non-blocking"
void SetNonBlocking(SocketHandle s, bool enable)
{
#ifdef _WIN32
    u_long mode = enable ? 1 : 0;
    ioctlsocket(s, FIONBIO, &mode);
#else
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, enable ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
#endif
}

// The heart of the scanner: try a full TCP connection to one port.
// Returns true if the port accepted the connection (= OPEN).
bool IsPortOpen(sockaddr_in address, int port, int timeoutMs)
{
    SocketHandle sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        return false;

    address.sin_port = htons(static_cast<unsigned short>(port));

    // Non-blocking connect means connect() returns straight away and we
    // decide ourselves how long to wait. Otherwise a filtered port could
    // make us wait ~20 seconds.
    SetNonBlocking(sock, true);
    connect(sock, reinterpret_cast<sockaddr*>(&address), sizeof(address));

    fd_set writeSet, errorSet;
    FD_ZERO(&writeSet);
    FD_ZERO(&errorSet);
    FD_SET(sock, &writeSet);
    FD_SET(sock, &errorSet);

    timeval timeout{};
    timeout.tv_sec = timeoutMs / 1000;
    timeout.tv_usec = (timeoutMs % 1000) * 1000;

    // select() waits until the socket is ready to write (connected),
    // has an error (refused), or the timeout runs out.
    bool open = false;
    int ready = select(static_cast<int>(sock) + 1, nullptr, &writeSet, &errorSet, &timeout);

    if (ready > 0 && FD_ISSET(sock, &writeSet))
    {
        // "Writable" can also mean "failed", so ask the socket for its error
        int error = 0;
        socklen_t len = sizeof(error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &len);
        open = (error == 0);
    }

    closesocket(sock);
    return open;
}

// ---------------------------------------------------------------------
//  Command-line interface
// ---------------------------------------------------------------------
void PrintBanner()
{
    std::cout <<
        "  ____            _   ____                                  \n"
        " |  _ \\ ___  _ __| |_/ ___|  ___ __ _ _ __  _ __   ___ _ __ \n"
        " | |_) / _ \\| '__| __\\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|\n"
        " |  __/ (_) | |  | |_ ___) | (_| (_| | | | | | | |  __/ |   \n"
        " |_|   \\___/|_|   \\__|____/ \\___\\__,_|_| |_|_| |_|\\___|_|   \n"
        "\n  TCP connect scanner  |  for authorised testing only\n\n";
}

void PrintUsage()
{
    std::cout <<
        "Usage:\n"
        "  PortScanner <target> [options]\n\n"
        "Options:\n"
        "  -p <start-end>   Port range to scan       (default 1-1024)\n"
        "  -p <port>        Scan a single port\n"
        "  -t <ms>          Timeout per port in ms   (default 500)\n"
        "  -j <threads>     Ports scanned at once    (default 100)\n"
        "  -o <file>        Save results to a text file\n"
        "  -y, --yes        Skip the permission confirmation\n"
        "  -h, --help       Show this help\n\n"
        "Examples:\n"
        "  PortScanner 127.0.0.1\n"
        "  PortScanner localhost -p 1-65535 -t 200 -j 300\n"
        "  PortScanner 192.168.1.10 -p 22 -o results.txt\n\n"
        "Only scan systems you own or have written permission to test.\n";
}

// Read a whole number safely; returns false if the text isn't a number
bool ParseInt(const std::string& text, int& value)
{
    try
    {
        size_t used = 0;
        value = std::stoi(text, &used);
        return used == text.size();
    }
    catch (...)
    {
        return false;
    }
}

bool ParseArguments(int argc, char* argv[], Options& opt)
{
    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];
        bool hasNext = (i + 1 < argc);

        if (arg == "-h" || arg == "--help")
        {
            return false;
        }
        else if (arg == "-y" || arg == "--yes")
        {
            opt.skipConfirm = true;
        }
        else if (arg == "-p" && hasNext)
        {
            std::string range = argv[++i];
            size_t dash = range.find('-');
            if (dash == std::string::npos)
            {
                if (!ParseInt(range, opt.startPort)) return false;
                opt.endPort = opt.startPort;
            }
            else
            {
                if (!ParseInt(range.substr(0, dash), opt.startPort)) return false;
                if (!ParseInt(range.substr(dash + 1), opt.endPort))  return false;
            }
        }
        else if (arg == "-t" && hasNext)
        {
            if (!ParseInt(argv[++i], opt.timeoutMs)) return false;
        }
        else if (arg == "-j" && hasNext)
        {
            if (!ParseInt(argv[++i], opt.threads)) return false;
        }
        else if (arg == "-o" && hasNext)
        {
            opt.outFile = argv[++i];
        }
        else if (!arg.empty() && arg[0] != '-' && opt.target.empty())
        {
            opt.target = arg;
        }
        else
        {
            std::cout << "Unknown or incomplete option: " << arg << "\n\n";
            return false;
        }
    }

    // Sanity checks so we never scan nonsense
    if (opt.target.empty()) { std::cout << "Error: no target given.\n\n"; return false; }
    if (opt.startPort < 1 || opt.endPort > 65535 ||
        opt.startPort > opt.endPort) {
        std::cout << "Error: ports must be 1-65535 and start <= end.\n\n"; return false;
    }
    if (opt.timeoutMs < 1 || opt.timeoutMs > 10000) { std::cout << "Error: timeout must be 1-10000 ms.\n\n"; return false; }
    if (opt.threads < 1 || opt.threads > 500) { std::cout << "Error: threads must be 1-500.\n\n"; return false; }

    return true;
}

// Loopback (127.x.x.x) is always your own machine
bool IsLocalhost(const std::string& ip)
{
    return ip.rfind("127.", 0) == 0;
}

// Ask the user to confirm they're allowed to scan this target
bool ConfirmPermission(const Options& opt, const std::string& ip)
{
    if (opt.skipConfirm || IsLocalhost(ip))
        return true;

    std::cout << "!! WARNING !!\n"
        << "Scanning computers without permission can be illegal\n"
        << "(e.g. the Computer Misuse Act in the UK, the CFAA in the US).\n\n"
        << "Do you own " << opt.target << " (" << ip << ") or have written\n"
        << "permission to scan it? Type 'yes' to continue: ";

    std::string answer;
    std::getline(std::cin, answer);
    return answer == "yes" || answer == "YES" || answer == "y";
}

// ---------------------------------------------------------------------
//  The scan itself (used by both modes below)
// ---------------------------------------------------------------------
int RunScanner(int argc, char* argv[])
{

    Options opt;
    if (!ParseArguments(argc, argv, opt))
    {
        PrintUsage();
        return 1;
    }

    if (!StartNetworking())
    {
        std::cout << "Could not start networking (WSAStartup failed).\n";
        return 1;
    }

    sockaddr_in address{};
    std::string ip;
    if (!ResolveTarget(opt.target, address, ip))
    {
        std::cout << "Could not resolve host: " << opt.target << "\n";
        StopNetworking();
        return 1;
    }

    if (!ConfirmPermission(opt, ip))
    {
        std::cout << "Scan cancelled.\n";
        StopNetworking();
        return 0;
    }

    int totalPorts = opt.endPort - opt.startPort + 1;
    int threadCount = std::min(opt.threads, totalPorts);

    std::cout << "Target   : " << opt.target << " (" << ip << ")\n"
        << "Ports    : " << opt.startPort << "-" << opt.endPort
        << " (" << totalPorts << " ports)\n"
        << "Timeout  : " << opt.timeoutMs << " ms   Threads: " << threadCount << "\n\n";

    // Shared between threads:
    std::atomic<int> nextPort(opt.startPort); // the next port nobody has taken yet
    std::atomic<int> done(0);                 // how many ports are finished
    std::vector<OpenPort> openPorts;
    std::mutex resultsLock;                   // stops two threads writing at once

    auto start = std::chrono::steady_clock::now();

    // Each worker keeps grabbing the next port until there are none left
    auto worker = [&]()
        {
            while (true)
            {
                int port = nextPort++;
                if (port > opt.endPort)
                    break;

                if (IsPortOpen(address, port, opt.timeoutMs))
                {
                    std::lock_guard<std::mutex> guard(resultsLock);
                    openPorts.push_back({ port, ServiceName(port) });
                }
                done++;
            }
        };

    std::vector<std::thread> workers;
    for (int i = 0; i < threadCount; i++)
        workers.emplace_back(worker);

    // Progress bar while the workers run
    while (done < totalPorts)
    {
        int percent = done * 100 / totalPorts;
        int filled = percent / 4;
        std::cout << "\r[" << std::string(filled, '#') << std::string(25 - filled, '.')
            << "] " << std::setw(3) << percent << "%  " << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::cout << "\r[" << std::string(25, '#') << "] 100%  \n\n";

    for (auto& t : workers)
        t.join();

    auto seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

    std::sort(openPorts.begin(), openPorts.end(),
        [](const OpenPort& a, const OpenPort& b) { return a.port < b.port; });

    // Build the report once so we can print it and save it
    std::ostringstream report;
    report << "PORT      STATE   SERVICE\n";
    report << "--------  ------  ---------------\n";
    for (const auto& p : openPorts)
    {
        report << std::left << std::setw(10) << (std::to_string(p.port) + "/tcp")
            << std::setw(8) << "open" << p.service << "\n";
    }
    report << "\n" << openPorts.size() << " open, "
        << (totalPorts - openPorts.size()) << " closed/filtered. "
        << "Scanned " << totalPorts << " ports on " << ip
        << " in " << std::fixed << std::setprecision(2) << seconds << "s.\n";

    std::cout << report.str();

    if (!opt.outFile.empty())
    {
        std::ofstream file(opt.outFile);
        if (file)
        {
            file << "PortScanner results for " << opt.target << " (" << ip << ")\n\n" << report.str();
            std::cout << "Results saved to " << opt.outFile << "\n";
        }
        else
        {
            std::cout << "Could not write to " << opt.outFile << "\n";
        }
    }

    StopNetworking();
    return 0;
}

// ---------------------------------------------------------------------
//  Interactive mode: when the program is started with no arguments
//  (e.g. double-clicked or Ctrl+F5), ask the user what to scan.
// ---------------------------------------------------------------------
int RunInteractive(const char* programName)
{
    std::string target, ports;

    std::cout << "No target given, so let's set one up.\n"
        << "(Tip: 127.0.0.1 means this computer.)\n\n"
        << "Target to scan [127.0.0.1]: ";
    std::getline(std::cin, target);
    if (target.empty()) target = "127.0.0.1";

    std::cout << "Ports, e.g. 1-1024 or 80     [1-1024]: ";
    std::getline(std::cin, ports);
    if (ports.empty()) ports = "1-1024";
    std::cout << "\n";

    // Build a pretend command line and reuse the normal scanner
    std::vector<std::string> args = { programName, target, "-p", ports };
    std::vector<char*> argv;
    for (auto& a : args)
        argv.push_back(&a[0]);

    int result = RunScanner(static_cast<int>(argv.size()), argv.data());

    // Keep the window open so the results can be read
    std::cout << "\nPress Enter to exit...";
    std::string ignore;
    std::getline(std::cin, ignore);
    return result;
}

// ---------------------------------------------------------------------
//  main
// ---------------------------------------------------------------------
int main(int argc, char* argv[])
{
    PrintBanner();

    if (argc == 1)
        return RunInteractive(argv[0]);

    return RunScanner(argc, argv);
}
