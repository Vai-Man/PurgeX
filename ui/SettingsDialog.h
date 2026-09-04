#ifndef SETTINGSDIALOG_H
#define SETTINGSDIALOG_H

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QComboBox>
#include <QPushButton>
#include <QGroupBox>
#include <QRadioButton>
#include <QButtonGroup>
#include <QCheckBox>
#include <QSlider>
#include <QSpinBox>
#include <QTabWidget>
#include <QWidget>

class SettingsDialog : public QDialog {
    Q_OBJECT

public:
    explicit SettingsDialog(QWidget *parent = nullptr);
    ~SettingsDialog();

private slots:
    void onThemeChanged();
    void onApplyClicked();
    void onOkClicked();
    void onCancelClicked();
    void onResetToDefaultsClicked();
    void onThemePreviewClicked();

private:
    void setupUI();
    void setupAppearanceTab();
    void setupAdvancedTab();
    void setupAboutTab();
    
    void loadCurrentSettings();
    void saveSettings();
    void applySettings();
    void resetToDefaults();
    
    void updateThemePreview();
    
    // Main layout
    QTabWidget *tabWidget;
    
    // Appearance tab
    QWidget *appearanceTab;
    QGroupBox *themeGroupBox;
    QComboBox *themeComboBox;
    QLabel *themePreviewLabel;
    QPushButton *previewButton;
    
    QGroupBox *uiGroupBox;
    QCheckBox *animationsCheckBox;
    QCheckBox *tooltipsCheckBox;
    QCheckBox *soundEffectsCheckBox;
    
    // Advanced tab
    QWidget *advancedTab;
    QGroupBox *performanceGroupBox;
    QCheckBox *hardwareAccelCheckBox;
    QCheckBox *multiThreadCheckBox;
    
    QGroupBox *securityGroupBox;
    QCheckBox *secureEraseCheckBox;
    QSlider *erasePatternsSlider;
    QLabel *erasePatternsLabel;
    
    // About tab
    QWidget *aboutTab;
    QLabel *appInfoLabel;
    QLabel *versionLabel;
    QLabel *authorLabel;
    QLabel *licenseLabel;
    
    // Dialog buttons
    QHBoxLayout *buttonLayout;
    QPushButton *okButton;
    QPushButton *applyButton;
    QPushButton *cancelButton;
    QPushButton *resetButton;
    
    // Settings storage
    int selectedTheme;
    bool settingsChanged;
};

#endif // SETTINGSDIALOG_H