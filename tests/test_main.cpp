#include <QApplication>
#include <QtTest/QtTest>

#include "test_wipe_verify.cpp"
#include "test_forensic_engine.cpp"
#include "test_cert_manager.cpp"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    int status = 0;
    
    {
        TestWipeVerify tc;
        status |= QTest::qExec(&tc, argc, argv);
    }
    {
        TestForensicEngine tc;
        status |= QTest::qExec(&tc, argc, argv);
    }
    {
        TestCertManager tc;
        status |= QTest::qExec(&tc, argc, argv);
    }
    
    return status;
}
