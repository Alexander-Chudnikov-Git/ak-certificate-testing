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
    case -100:
      return "Попытка доступа к неопределенной опции библиотеки.";
    case -101:
      return "Ошибка использования неправильного (неожидаемого) значения.";
    case -110:
      return "Неверный тип криптографического механизма.";
    case -111:
      return "Неверный режим использования криптографического механизма.";
    case -112:
      return "Ошибочное или не определенное имя криптографического механизма.";
    case -113:
      return "Ошибочный или неопределенный идентификатор криптографического механизма.";
    case -114:
      return "Ошибочный индекс идентификатора криптографического механизма.";
    case -115:
      return "Ошибка с обращением к oid.";
    case -120:
      return "Ошибка, возникающая когда параметры кривой не соответствуют алгоритму, в котором они используются.";
    case -121:
      return "Ошибка, возникающая если точка не принадлежит заданной кривой.";
    case -122:
      return "Ошибка, возникающая когда порядок точки неверен.";
    case -123:
      return "Ошибка, возникающая если дискриминант кривой равен нулю (уравнение не задает кривую).";
    case -124:
      return "Ошибка, возникающая когда неверно определены вспомогательные параметры эллиптической кривой.";
    case -125:
      return "Ошибка, возникающая когда простой модуль кривой задан неверно.";
    case -126:
      return "Ошибка, возникающая при сравнении двух эллиптических кривых";
    case -130:
      return "Ошибка, возникающая при использовании ключа, значение которого не определено.";
    case -131:
      return "Ошибка, возникающая при использовании ключа для бесключевых функций.";
    case -132:
      return "Ошибка, возникающая при неверном заполнении полей структуры bckey.";
    case -133:
      return "Ошибка, возникающая при зашифровании/расшифровании данных, длина которых не кратна длине блока.";
    case -134:
      return "Ошибка, возникающая при неверном значении кода целостности ключа.";
    case -135:
      return "Ошибка, возникающая при неверном значении длины ключа.";
    case -136:
      return "Ошибка, возникающая при использовании неверного типа ключа.";
    case -137:
      return "Ошибка, возникающая при недостаточном ресурсе ключа.";
    case -138:
      return "Ошибка, возникающая при использовании синхропосылки (инициализационного вектора) неверной длины.";
    case -139:
      return "Ошибка, возникающая при неправильном использовании функций зашифрования/расшифрования данных.";
    case -140:
      return "Ошибка согласования данных.";
    case -150:
      return "Использование неверного значения поля, определяющего тип данных";
    case -151:
      return "Использование неверного значения длины данных, размещаемых в узле ASN1 дерева";
    case -152:
      return "Использование неверной функции для чтения отрицательных данных, размещаемых в узле ASN1 дерева";
    case -153:
      return "Полученные ASN.1 данные содержат неверный или неожидаемый контент";
    case -154:
      return "Полученные ASN.1 данные содержат неверное количество элементов";
    case -155:
      return "Ошибка, возникающая при кодировании ASN1 структуры (перевод в DER-кодировку).";
    case -156:
      return "Ошибка, возникающая при декодировании ASN1 структуры (перевод из DER-кодировки в ASN1 структуру).";
    case -160:
      return "Ошибка использования для проверки сертификата неопределенного открытого ключа (null указатель)";
    case -161:
      return "Ошибка использования для проверки сертификата открытого ключа с некорректным или не поддерживаемым алгоритмом электронной подписи.";
    case -162:
      return "Ошибка использования для проверки сертификата открытого ключа, расширенное имя владельца которого не совпадает с именем эмитента в проверяемом сертификате.";
    case -165:
      return "Ошибка при импорте/экспорте сертификата: срок действия сертификата не актуален (истек или еще не начался)";
    case -166:
      return "Ошибка при импорте/экспорте сертификата: сертификат не является сертификатом центра сертификации.";
    case -167:
      return "Ошибка при импорте сертификата: сертификат не содержит установленный бит в расширении keyUsage.";
    case -168:
      return "Ошибка при импорте сертификата: сертификат предназначен для некорректного или неподдерживаемого алгоритма электронной подписи.";
    case -169:
      return "Ошибка при импорте сертификата: электроннная подпись под сертификатом не верна.";
    case -170:
      return "Ошибка при проверке электроннной подписи под произвольными данными";
    case -180:
      return "Ошибка при выборе схемы асимметричного шифрования";
    case -181:
      return "Ошибка использования не инициализированного aead контекста";
    default:
      return "Неизвестный код ошибки.";
  }
}

}

