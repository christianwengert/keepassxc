#ifndef ENTROPY_EVENT_FILTER_H
#define ENTROPY_EVENT_FILTER_H

#include <QEvent>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QObject>
#include <QRandomGenerator>
#include <QtCore/QCryptographicHash>
#include <botan/hash.h>

class EntropyEventFilter : public QObject {
    Q_OBJECT
public:
    static EntropyEventFilter& instance();  // Singleton access method

    QByteArray getHashedEntropy(); // Returns the 32-byte hash

protected:
    bool eventFilter(QObject *obj, QEvent *event) override;

private:
    EntropyEventFilter();                   // Private constructor
    EntropyEventFilter(const EntropyEventFilter&) = delete;             // Disable copy constructor
    EntropyEventFilter& operator=(const EntropyEventFilter&) = delete;  // Disable assignment

    std::unique_ptr<Botan::HashFunction> hash;

    int counter;



};

#endif // ENTROPY_EVENT_FILTER_H