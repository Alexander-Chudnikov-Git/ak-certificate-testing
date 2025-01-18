 /**
 * @file       <certificate-processing.hpp>
 * @brief      Заголовочный файл для класса CertificateProcessing
 *
 *             Данный класс занимается подгрузкой и обработкой сертификатов.
 *
 * @author     CHOO_IS_FOX (@Alexander-Chudnikov-Git)
 * @date       19.01.2025
 * @version    0.0.1
 *
 * @warning    Данная версия класса не является окончательной и нуждается в
 *             тестировании.
 *
 * @bug        На данный момент баги отсутсвуют.
 *
 *             Список ранее исправленных багов:
 *              - Исправлена утечка памяти связанная с тем, что this->ak_cert не
 *                удалялся в деструкторе
 *              - Исправлена ошибка при которой дамп сертификата мог происходить
 *                без загрузки самого сертификата.
 *              - Исправлена ошибка при которой происходил доступ к
 *                неинициализированной переменной внутри функции
 *                ak_certificate_destroy.
 *              - Исправленна ошибка при которой невозможно было загрузить
 *                сертификат второй раз.
 *              - Ошибки akrypt переведены на английский
 *
 * @copyright  А. А. Чудников, 2025
 *
 * @license    Данный проект находится под публичной лицензией GNUv3.
 *
 * @todo       Список будующих задач:
 *              - Провети нормальное тестирование
 */

#ifndef CERTIFICATE_PROCESSING_HPP
#define CERTIFICATE_PROCESSING_HPP

#include <string>
#include <string_view>

#include <libakrypt-base.h> ///< Хэдеры Akrypt загружается в последнюю очередь, так как в противном случае возникают ошибки компиляции
#include <libakrypt.h>

namespace CHDK
{
/**
 * @brief      Класс для обработки сертификатов и выполнения криптографических
 *             операций с использованием библиотеки akrypt.
 */
class CertificateProcessing
{
public:
    /**
     * @brief  Конструктор класса CertificateProcessing.
     *
     *         Инициализирует переменные класса и вызывает инициализатор
     *         библиотеки akrypt.
     *
     */
    CertificateProcessing();

    /**
     * @brief  Деструктор класса.
     *
     *         Освобождает ресурсы, занятые библиотекой akrypt, а так же
     *         сертификатом.
     */
    ~CertificateProcessing();

    /**
     * @brief  Производит попытку загрузки сертификата из файла.
     *
     *         В случае удачи устанавливает флаг ak_certificate_loaded.
     *         При неудчаной попытке, сбрасывает последний.
     *
     * @param  certificate_path  Путь к файлу сертификата.
     */
    void loadCertificate(const std::string& certificate_path);

    /**
     * @brief  Выводит информацию о загруженном сертификате.
     *
     *         В частности выводит номер, дату истечения срока действия,
     *         название, публичный ключ, название эллиптической кривой,
     *         кратную точку, а так же информацию о том, лежат ли выше описанные
     *         точки на данной эллиптической кривой.
     */
    void dumpCertificate();

private:
    /**
     * @brief  Инициализирует библиотеку libakrypt.
     */
    void initLibAkrypt();

    /**
     * @brief  Проверяет, инициализирована ли библиотека libakrypt.
     *
     * @return true, если библиотека инициализирована, иначе false.
     */
    bool isLibAkryptInit();

    /**
     * @brief  Проверяет, находится ли точка на кривой.
     *
     * @param  local_wpoint      Точка для проверки.
     *
     * @return true, если точка находится на кривой, иначе false.
     */
    bool isPointOnCurve(struct wpoint& local_wpoint);

    /**
     * @brief  Генерирует случайный скаляр K.
     *
     * @param  k                 Скаляр в виде массива из 8 64-битных целых чисел.
     * @return true, если генерация прошла успешно, иначе false.
     */
    bool generateRandomK(ak_uint64 (&k)[8]);

    /**
     * @brief  Возвращает описание ошибки libakrypt по ее коду.
     *
     * @param  error             Код ошибки.
     * @return Описание ошибки в виде std::string_view.
     */
    std::string_view getAkErrorDescription(int error);

    /**
     * @brief  Возвращает общее имя (Common Name) из сертификата.
     *
     * @return Общее имя в виде std::string_view.
     *         Если общее имя не найдено, возвращает "Unknown CN".
     */
    std::string_view getCertificateCommonName();

    /**
     * @brief Возвращает дату истечения срока действия сертификата.
     *
     * @return Дата истечения срока действия в виде std::string_view,
     *         отформатированную как "DD MMM YYYY".
     *         Если дату не удалось получить, возвращает "Invalid Time".
     */
    std::string_view getCertificateExpirationDate();

    /**
     * @brief  Возвращает серийный номер сертификата.
     *
     * @return Серийный номер в виде std::string_view.
     *         Если серийный номер слишком длинный, он обрезается и добавляется
     *         "..." в конце.
     */
    std::string_view getCertificateSerialNumber();

     /**
     * @brief  Возвращает имя кривой, используемой в сертификате.
     *
     * @return Имя кривой в виде std::string_view.
     */
    std::string_view getCertificateCurveName();

    /**
     * @brief  Извлекает координаты X, Y и Z из точки.
     *
     * @param  local_wpoint      Точка на кривой.
     *
     * @return Кортеж из трех строк, представляющих координаты X, Y и Z в
     *         шестнадцатеричном формате.
     */
    std::tuple<std::string, std::string, std::string> extractPointCoordinates(struct wpoint& local_wpoint);

    /**
     * @brief  Вычисляет произведение точки на скаляр.
     *
     * @param  k                 Скаляр в виде массива из 8 64-битных целых чисел.
     *
     * @return Кортеж из трех строк, представляющих координаты X, Y и Z
     *         результирующей точки в шестнадцатеричном формате.
     */
    std::tuple<std::string, std::string, std::string> calculateMultiplePoint(ak_uint64 (&k)[8]);

private:
    bool ak_initialized;        ///< Флаг, указывающий, инициализирована ли библиотека libakrypt.
    bool ak_certificate_loaded; ///< Флаг, указывающий, загружен ли сертификат.

    ak_certificate ak_cert    = {nullptr};  ///< Указатель на объект сертификата.
    ak_function_log *ak_audit = {nullptr};  ///< Указатель на функцию аудита libakrypt.
};
}

#endif // CERTIFICATE_PROCESSING_HPP

