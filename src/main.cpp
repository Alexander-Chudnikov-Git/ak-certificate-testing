#include <cxxopts.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "certificate-processing.hpp"

void logProjectInfo()
{
    spdlog::info("===========================================================");
    spdlog::info(" Project Information");
    spdlog::info("-----------------------------------------------------------");
    spdlog::info(" Project Name: {:<24} {}", PROJECT_NAME, PROJECT_VERSION);
    spdlog::info(" Compile Time: {}", COMPILE_TIME);
    spdlog::info(" Compiler:     {:<24} {}", COMPILER_ID, COMPILER_VERSION);
    spdlog::info("===========================================================");
}

void logCommandLineArguments(const int argc, const char *argv[])
{
    spdlog::info("-----------------------------------------------------------");
    spdlog::info(" Command-Line Arguments");
    spdlog::info("-----------------------------------------------------------");
    spdlog::info(" Argument Count: {}", argc);
    for (int i = 0; i < argc; ++i) {
        spdlog::info(" Argument [{}]: {}", i, argv[i]);
    }
    spdlog::info("===========================================================");
}

cxxopts::ParseResult parseCommandLineOptions(const int argc, const char *argv[])
{
    cxxopts::Options options(argv[0], "Certificate Loading Application");
    options.add_options()
        ("c,certificate", "Path to the certificate file", cxxopts::value<std::string>())
        ("d,dump", "Dump the certificate");

    try
    {
        return options.parse(argc, argv);
    }
    catch (const cxxopts::exceptions::exception& e)
    {
        spdlog::error(" Error parsing command line options: {}", e.what());
        exit(1);
    }
}

int main(const int argc, const char *argv[])
{
    logProjectInfo();
    logCommandLineArguments(argc, argv);

    cxxopts::ParseResult result = parseCommandLineOptions(argc, argv);

    std::string certificate_path;
    if (result.count("certificate"))
    {
        certificate_path = result["certificate"].as<std::string>();
    }

    bool dump_certificate = result.count("dump") > 0;

    auto certificate_processor = CHDK::CertificateProcessing();

    if (!certificate_path.empty())
    {
        certificate_processor.loadCertificate(certificate_path);
    }
    else
    {
        spdlog::error(" No certificate path provided.");
        return 1;
    }

    if (dump_certificate)
    {
        spdlog::info(" Dumping certificate.");
        spdlog::info("===========================================================");
        certificate_processor.dumpCertificate();
        spdlog::info("===========================================================");
    }

    return 0;
}
