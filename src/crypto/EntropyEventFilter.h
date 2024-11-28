#ifndef ENTROPY_EVENT_FILTER_H
#define ENTROPY_EVENT_FILTER_H

#include <QEvent>
#include <QMouseEvent>
#include <botan/hash.h>

#define ENTROPY_HASH_FUNCTION "SHA-3(256)"

class EntropyEventFilter : public QObject {
    Q_OBJECT
public:
    static EntropyEventFilter& instance();  // Singleton access method

protected:
    bool eventFilter(QObject *obj, QEvent *event) override;

private:
    EntropyEventFilter();                   // Private constructor
    EntropyEventFilter(const EntropyEventFilter&) = delete;             // Disable copy constructor
    EntropyEventFilter& operator=(const EntropyEventFilter&) = delete;  // Disable assignment
    Botan::secure_vector<uint8_t> entropyPool;
    qint64 lastReseedTime = 0;
};

#endif // ENTROPY_EVENT_FILTER_H