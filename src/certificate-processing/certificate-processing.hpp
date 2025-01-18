#ifndef CERTIFICATE_PROCESSING_HPP
#define CERTIFICATE_PROCESSING_HPP

#include <string>
#include <string_view>

#include <libakrypt-base.h>
#include <libakrypt.h>

namespace CHDK
{
class CertificateProcessing
{
public:
    CertificateProcessing();
    ~CertificateProcessing();

    void loadCertificate(const std::string& certificate_path);
    void dumpCertificate();

private:
    void initLibAkrypt();
    bool checkLibAkryptInit();

    constexpr std::string_view getAkErrorDescription(int error);

    std::string_view getCertificateCommonName();
    std::string_view getCertificateExpirationDate();
    std::string_view getCertificateSerialNumber();
    std::string_view getCertificateCurveName();

    std::tuple<std::string, std::string, std::string> extractKeyCoordinates(struct wpoint& local_wpoint);
    std::tuple<std::string, std::string, std::string> calculateMultiplePoint(ak_uint64 (&k)[8]);

    bool generateRandomK(ak_uint64 (&k)[8]);
    bool isPointOnCurve(struct wpoint& local_wpoint);

private:
    ak_function_log *ak_audit = {nullptr};
    ak_certificate ak_cert;

    bool ak_initialized;
};
}

#endif // CERTIFICATE_PROCESSING_HPP

