#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/fmt/ostr.h>

#include "certificate-processing.hpp" ///< Хэдеры Akrypt загружается в последнюю очередь, так как в противном случае возникают ошибки компиляции

namespace CHDK
{
CertificateProcessing::CertificateProcessing() :
    ak_initialized(false), ak_certificate_loaded(false), ak_cert(new struct certificate)
{
    this->ak_cert->vkey = {}; ///< Если не инициализировать данные структуры, визникает ошибка доступка к неинициализированной переменной при вызове ak_certificate_destroy, если сертификат не был загружен
    this->ak_cert->opts = {}; ///< Аналогично

    this->initLibAkrypt(); ///< Инициализация библиотеки Akrypt
}

CertificateProcessing::~CertificateProcessing()
{
    ak_libakrypt_destroy();

    if (this->ak_cert != nullptr) ///< Данная проверка нужна только для delete
    {
        ak_certificate_destroy(this->ak_cert);
        delete this->ak_cert;
    }

    this->ak_audit = nullptr; ///< Чистим указатель на всякий случай
}

void CertificateProcessing::loadCertificate(const std::string& certificate_path)
{
    if (!this->isLibAkryptInit())
    {
        return;
    }
    spdlog::info(" Started loading certificate.");

    ak_certificate_loaded = false;

    int error = ak_error_ok;

    error = ak_certificate_opts_create(&this->ak_cert->opts);

    spdlog::info(" Loaded certificate options.");

    if (error != ak_error_ok)
    {
        spdlog::error(" Unable to generate certificate options. {}", this->getAkErrorDescription(error));
        return;
    }

    error = ak_certificate_import_from_file(this->ak_cert, nullptr, certificate_path.c_str());

    if (error != ak_error_ok)
    {
        spdlog::error(" Unable to import certificate options. {}", this->getAkErrorDescription(error));
        return;
    }

    this->ak_certificate_loaded = true;

    spdlog::info(" Cerfificate {} loaded.", certificate_path);

    return;
}

void CertificateProcessing::dumpCertificate()
{
    if (!this->isLibAkryptInit())
    {
        return;
    }

    if (this->ak_cert == nullptr || !ak_certificate_loaded)
    {
        spdlog::error(" Certificate is not loaded.");
        return;
    }

    std::string_view cname       = this->getCertificateCommonName();
    std::string_view time_buffer = this->getCertificateExpirationDate();
    std::string_view serial_str  = this->getCertificateSerialNumber();

    spdlog::info(" {:<10} {:<12} {}", serial_str, time_buffer, cname); ///< Вывод информации о номере, дате истечения срока действия, и названия сертификата

    auto [pubkey_x_str, pubkey_y_str, pubkey_z_str] = this->extractPointCoordinates(this->ak_cert->vkey.qpoint);
    std::string_view curve_str = this->getCertificateCurveName();

    spdlog::info(" Public key: x-{}", pubkey_x_str); ///< Вывод информации о публичном ключе
    spdlog::info("             y-{}", pubkey_y_str);
    spdlog::info("             z-{}", pubkey_z_str);

    spdlog::info(" Curve:      {}", curve_str); ///< Вывод названия эллиптической кривой

    if (this->isPointOnCurve(this->ak_cert->vkey.qpoint)) ///< Проверка точки на предмет того, лежит ли она на кривой
    {
        spdlog::info(" Public key is on the curve");
    }
    else
    {
        spdlog::warn(" Public key is NOT on the curve");
    }

    ak_uint64 k_val[8];

    if (!this->generateRandomK(k_val))
    {
        return;
    }

    auto [mwp_x_str, mwp_y_str, mwp_z_str] = this->calculateMultiplePoint(k_val);

    spdlog::info(" K: {}", ak_mpzn_to_hexstr(k_val, ak_hash_get_tag_size(&this->ak_cert->vkey.ctx)>>3)); ///< Вывод раномно сгенерированного скаляра

    spdlog::info(" Multiple point: x-{}", mwp_x_str); ///< Вывод информации о кратной точке
    spdlog::info("                 y-{}", mwp_y_str);
    spdlog::info("                 z-{}", mwp_z_str);

    if (this->isPointOnCurve(this->ak_cert->vkey.qpoint)) ///< Проверка кратной точки на предмет того, лежит ли она на кривой
    {
        spdlog::info(" Multiple point is on the curve");
    }
    else
    {
        spdlog::warn(" Multiple point is NOT on the curve");
    }
}

std::string_view CertificateProcessing::getCertificateCommonName()
{
    std::string_view cname = "Unknown CN";
    ak_uint8* cname_raw = ak_tlv_get_string_from_global_name(this->ak_cert->opts.subject, "2.5.4.3", nullptr); ///< Достаем CN из сертификата

    if (cname_raw != nullptr)
    {
        cname = std::string_view(reinterpret_cast<char*>(cname_raw));
    }
    return cname;
}

std::string_view CertificateProcessing::getCertificateExpirationDate()
{
    static std::string formatted_date;
    std::time_t not_after = this->ak_cert->opts.time.not_after; ///< Достаем дату истечения срока действия
    std::tm time_info;

    if (localtime_r(&not_after, &time_info))
    {
        formatted_date = fmt::format(" {:02} {:3} {:4}",
                                     time_info.tm_mday,
                                     std::string_view("JanFebMarAprMayJunJulAugSepOctNovDec")
                                         .substr(time_info.tm_mon * 3, 3),
                                     1900 + time_info.tm_year);  ///< Конвертируем дату в читаемый формат

        return std::string_view(formatted_date);
    }
    else
    {
        return "Invalid Time";
    }
}

std::string_view CertificateProcessing::getCertificateSerialNumber()
{
    std::string_view serial_str = ak_ptr_to_hexstr(this->ak_cert->opts.serialnum, this->ak_cert->opts.serialnum_length, ak_false); ///< Достаем серийный номер сертификата

    if (this->ak_cert->opts.serialnum_length >= 18)
    {
        serial_str = serial_str.substr(0, 36);
        serial_str = std::string(serial_str) + "...";
    }
    return serial_str;
}

std::string_view CertificateProcessing::getCertificateCurveName()
{
    return ak_oid_find_by_data(this->ak_cert->vkey.wc)->name[0]; ///< Достаем название кривой
}

bool CertificateProcessing::isPointOnCurve(struct wpoint& local_wpoint)
{
    return ak_wpoint_is_ok(&local_wpoint, this->ak_cert->vkey.wc); ///< Проверяем лежит ли точка на кривой
}

std::tuple<std::string, std::string, std::string> CertificateProcessing::extractPointCoordinates(struct wpoint& local_wpoint)
{
    size_t ts = ak_hash_get_tag_size(&this->ak_cert->vkey.ctx);

    std::string pubkey_x_str = ak_mpzn_to_hexstr(local_wpoint.x, ( ts>>3 )); ///< Вытаскиваем из точки отдельные координаты
    std::string pubkey_y_str = ak_mpzn_to_hexstr(local_wpoint.y, ( ts>>3 ));
    std::string pubkey_z_str = ak_mpzn_to_hexstr(local_wpoint.z, ( ts>>3 ));

    return std::make_tuple(pubkey_x_str, pubkey_y_str, pubkey_z_str);
}

std::tuple<std::string, std::string, std::string> CertificateProcessing::calculateMultiplePoint(ak_uint64 (&k)[8])
{
    struct wpoint multiple_wpoint;

    auto pubkey_wpoint = this->ak_cert->vkey.qpoint;
    auto pubkey_wcurve = this->ak_cert->vkey.wc;
    ak_wpoint_pow(&multiple_wpoint, &pubkey_wpoint, k, pubkey_wcurve->size, pubkey_wcurve); ///< Возводим точку в кратную степень

    size_t ts = ak_hash_get_tag_size(&this->ak_cert->vkey.ctx);
    std::string mwp_x_str = ak_mpzn_to_hexstr(multiple_wpoint.x, ( ts>>3 )); ///< Вытаскиваем из кратной точки отдельные координаты
    std::string mwp_y_str = ak_mpzn_to_hexstr(multiple_wpoint.y, ( ts>>3 ));
    std::string mwp_z_str = ak_mpzn_to_hexstr(multiple_wpoint.z, ( ts>>3 ));

    return std::make_tuple(mwp_x_str, mwp_y_str, mwp_z_str);
}

bool CertificateProcessing::generateRandomK(ak_uint64 (&k)[8])
{
    struct random generator;

    if (ak_random_create_lcg(&generator) != ak_error_ok) ///< Инициализируем генератор рандомных чисел
    {
        spdlog::error(" Unable to initialize LCG random number generator.");
        return false;
    }

    if (ak_random_ptr(&generator, k, sizeof(k)) != ak_error_ok) ///< Генерируем случайное значение
    {
        spdlog::error(" Failed to generate random values.");
        ak_random_destroy(&generator);
        return false;
    }

    ak_random_destroy(&generator);

    return true;
}

void CertificateProcessing::initLibAkrypt()
{
    this->ak_audit = ak_function_log_syslog;

    if (ak_libakrypt_create(this->ak_audit) != ak_true) ///< Инициализируем akrypt
    {
        this->ak_initialized = false;

        ak_libakrypt_destroy();
        this->ak_audit = nullptr;
        return;
    }
    this->ak_initialized = true;
}

bool CertificateProcessing::isLibAkryptInit()
{
    if (this->ak_initialized && this->ak_audit != nullptr) ///< Проверяем инициализирован ли akrypt
    {
        return true;
    }

    spdlog::error(" Akrypt is not initialized.");
    return false;
}

std::string_view CertificateProcessing::getAkErrorDescription(int error)
{
  switch (error)
  {
    case ak_error_wrong_option:
      return "Attempt to access an undefined library option.";
    case ak_error_invalid_value:
      return "Error using incorrect (unexpected) value.";
    case ak_error_oid_engine:
      return "Incorrect type of cryptographic mechanism.";
    case ak_error_oid_mode:
      return "Incorrect mode of using cryptographic mechanism.";
    case ak_error_oid_name:
      return "Incorrect or undefined name of cryptographic mechanism.";
    case ak_error_oid_id:
      return "Incorrect or undefined identifier of cryptographic mechanism.";
    case ak_error_oid_index:
      return "Incorrect index of identifier of cryptographic mechanism.";
    case ak_error_wrong_oid:
      return "Error accessing oid.";
    case ak_error_curve_not_supported:
      return "Error that occurs when the curve parameters do not match the algorithm in which they are used.";
    case ak_error_curve_point:
      return "Error that occurs if the point does not belong to the given curve.";
    case ak_error_curve_point_order:
      return "Error that occurs when the order of the point is incorrect.";
    case ak_error_curve_discriminant:
      return "Error that occurs if the discriminant of the curve is zero (the equation does not define a curve).";
    case ak_error_curve_order_parameters:
      return "Error that occurs when the auxiliary parameters of the elliptic curve are incorrectly defined.";
    case ak_error_curve_prime_modulo:
      return "Error that occurs when the prime modulus of the curve is set incorrectly.";
    case ak_error_curve_not_equal:
      return "Error that occurs when comparing two elliptic curves.";
    case ak_error_key_value:
      return "Error that occurs when using a key whose value is undefined.";
    case ak_error_key_usage:
      return "Error that occurs when using a key for keyless functions.";
    case ak_error_wrong_block_cipher:
      return "Error that occurs when the fields of the bckey structure are incorrectly filled.";
    case ak_error_wrong_block_cipher_length:
      return "Error that occurs when encrypting/decrypting data whose length is not a multiple of the block length.";
    case ak_error_wrong_key_icode:
      return "Error that occurs when the key integrity code is incorrect.";
    case ak_error_wrong_key_length:
      return "Error that occurs when the key length is incorrect.";
    case ak_error_wrong_key_type:
      return "Error that occurs when using an incorrect key type.";
    case ak_error_low_key_resource:
      return "Error that occurs when there is insufficient key resource.";
    case ak_error_wrong_iv_length:
      return "Error that occurs when using an incorrect length of synchronization vector (initialization vector).";
    case ak_error_wrong_block_cipher_function:
      return "Error that occurs when incorrectly using data encryption/decryption functions.";
    case ak_error_linked_data:
      return "Data agreement error.";
    case ak_error_invalid_asn1_tag:
      return "Using an incorrect value of the field that determines the data type.";
    case ak_error_invalid_asn1_length:
      return "Using an incorrect data length value placed in the ASN1 tree node.";
    case ak_error_invalid_asn1_significance:
      return "Using an incorrect function to read negative data placed in the ASN1 tree node.";
    case ak_error_invalid_asn1_content:
      return "The received ASN.1 data contains incorrect or unexpected content.";
    case ak_error_invalid_asn1_count:
      return "The received ASN.1 data contains an incorrect number of elements.";
    case ak_error_wrong_asn1_encode:
      return "Error that occurs when encoding an ASN1 structure (translation to DER encoding).";
    case ak_error_wrong_asn1_decode:
      return "Error that occurs when decoding an ASN1 structure (translation from DER encoding to an ASN1 structure).";
    case ak_error_certificate_verify_key:
      return "Error using an undefined public key (null pointer) to verify the certificate.";
    case ak_error_certificate_verify_engine:
      return "Error using a public key with an incorrect or unsupported digital signature algorithm to verify the certificate.";
    case ak_error_certificate_verify_names:
      return "Error using a public key to verify the certificate, the extended owner name of which does not match the issuer name in the verified certificate.";
    case ak_error_certificate_validity:
      return "Error when importing/exporting a certificate: the certificate's validity period is not current (expired or has not yet begun).";
    case ak_error_certificate_ca:
      return "Error when importing/exporting a certificate: the certificate is not a CA certificate.";
    case ak_error_certificate_key_usage:
      return "Error when importing a certificate: the certificate does not contain the set bit in the keyUsage extension.";
    case ak_error_certificate_engine:
      return "Error when importing a certificate: the certificate is intended for an incorrect or unsupported digital signature algorithm.";
    case ak_error_certificate_signature:
      return "Error when importing a certificate: the digital signature under the certificate is not valid.";
    case ak_error_signature:
      return "Error when verifying the digital signature under arbitrary data.";
    case ak_error_encrypt_scheme:
      return "Error when choosing an asymmetric encryption scheme.";
    case ak_error_aead_initialization:
      return "Error using an uninitialized aead context.";
    default:
      return "Unknown error code.";
  }
}

}

