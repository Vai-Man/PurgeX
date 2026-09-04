#include "SettingsDialog.h"
#include <QApplication>
#include <QScreen>
#include <QMessageBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QSpacerItem>
#include <QSizePolicy>
#include <QFont>
#include <QSettings>
#include <QFrame>
#include <QIcon>
#include <QGuiApplication>
#include <QStringList>

SettingsDialog::SettingsDialog(QWidget *parent)
    : QDialog(parent)
    , tabWidget(nullptr)
    , selectedTheme(0)
    , settingsChanged(false)
{
    setupUI();
    loadCurrentSettings();
    
    // Set dialog properties
    setWindowTitle("PurgeX Settings");
    setWindowIcon(QIcon(":/icons/settings.png"));
    setModal(true);
    setMinimumSize(500, 400);
    resize(600, 500);
    
    // Center the dialog
    QScreen *screen = QGuiApplication::primaryScreen();
    if (screen) {
        QRect screenGeometry = screen->geometry();
        int x = (screenGeometry.width() - width()) / 2;
        int y = (screenGeometry.height() - height()) / 2;
        move(x, y);
    }
}

SettingsDialog::~SettingsDialog() {
}

void SettingsDialog::setupUI() {
    // Main layout
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(16);
    mainLayout->setContentsMargins(20, 20, 20, 20);
    
    // Tab widget
    tabWidget = new QTabWidget(this);
    tabWidget->setObjectName("settingsTabWidget");
    
    // Setup tabs
    setupAppearanceTab();
    setupAdvancedTab();
    setupAboutTab();
    
    mainLayout->addWidget(tabWidget);
    
    // Separator line
    QFrame *separator = new QFrame(this);
    separator->setFrameShape(QFrame::HLine);
    separator->setFrameShadow(QFrame::Sunken);
    mainLayout->addWidget(separator);
    
    // Dialog buttons
    buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(12);
    
    resetButton = new QPushButton("Reset to Defaults", this);
    resetButton->setObjectName("resetButton");
    
    QSpacerItem *buttonSpacer = new QSpacerItem(0, 0, QSizePolicy::Expanding, QSizePolicy::Minimum);
    
    cancelButton = new QPushButton("Cancel", this);
    cancelButton->setObjectName("cancelButton");
    cancelButton->setProperty("flat", true);
    
    applyButton = new QPushButton("Apply", this);
    applyButton->setObjectName("applyButton");
    applyButton->setEnabled(false);
    
    okButton = new QPushButton("OK", this);
    okButton->setObjectName("okButton");
    okButton->setDefault(true);
    
    buttonLayout->addWidget(resetButton);
    buttonLayout->addItem(buttonSpacer);
    buttonLayout->addWidget(cancelButton);
    buttonLayout->addWidget(applyButton);
    buttonLayout->addWidget(okButton);
    
    mainLayout->addLayout(buttonLayout);
    
    // Connect signals
    connect(themeComboBox, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, &SettingsDialog::onThemeChanged);
    connect(previewButton, &QPushButton::clicked, this, &SettingsDialog::onThemePreviewClicked);
    connect(okButton, &QPushButton::clicked, this, &SettingsDialog::onOkClicked);
    connect(applyButton, &QPushButton::clicked, this, &SettingsDialog::onApplyClicked);
    connect(cancelButton, &QPushButton::clicked, this, &SettingsDialog::onCancelClicked);
    connect(resetButton, &QPushButton::clicked, this, &SettingsDialog::onResetToDefaultsClicked);
}

void SettingsDialog::setupAppearanceTab() {
    appearanceTab = new QWidget();
    appearanceTab->setObjectName("appearanceTab");
    
    QVBoxLayout *layout = new QVBoxLayout(appearanceTab);
    layout->setSpacing(20);
    layout->setContentsMargins(16, 16, 16, 16);
    
    // Theme selection group
    themeGroupBox = new QGroupBox("Theme Selection", appearanceTab);
    themeGroupBox->setObjectName("themeGroupBox");
    
    QVBoxLayout *themeLayout = new QVBoxLayout(themeGroupBox);
    themeLayout->setSpacing(12);
    
    // Theme description
    QLabel *themeDescLabel = new QLabel("Choose your preferred visual theme:", themeGroupBox);
    themeDescLabel->setObjectName("subtitle");
    themeLayout->addWidget(themeDescLabel);
    
    // Theme combo box
    themeComboBox = new QComboBox(themeGroupBox);
    themeComboBox->setObjectName("themeComboBox");
    themeComboBox->addItems(QStringList() << "Default Light" << "Professional Dark" << "Pitch Black");
    themeComboBox->setMinimumHeight(40);
    themeLayout->addWidget(themeComboBox);
    
    // Theme preview
    QHBoxLayout *previewLayout = new QHBoxLayout();
    
    themePreviewLabel = new QLabel("Preview the selected theme:", themeGroupBox);
    previewLayout->addWidget(themePreviewLabel);
    
    previewButton = new QPushButton("Preview Theme", themeGroupBox);
    previewButton->setObjectName("previewThemeButton");
    previewButton->setMaximumWidth(120);
    previewLayout->addWidget(previewButton);
    
    previewLayout->addStretch();
    themeLayout->addLayout(previewLayout);
    
    // Theme descriptions
    QLabel *themeInfoLabel = new QLabel(
        "<b>Default Light:</b> Clean, bright interface perfect for daytime use<br>"
        "<b>Professional Dark:</b> Elegant dark theme for extended coding sessions<br>"
        "<b>Pitch Black:</b> Ultra-dark theme with purple accents for maximum contrast",
        themeGroupBox);
    themeInfoLabel->setObjectName("themeInfoLabel");
    themeInfoLabel->setWordWrap(true);
    themeLayout->addWidget(themeInfoLabel);
    
    layout->addWidget(themeGroupBox);
    
    // UI Options group
    uiGroupBox = new QGroupBox("Interface Options", appearanceTab);
    uiGroupBox->setObjectName("uiGroupBox");
    
    QVBoxLayout *uiLayout = new QVBoxLayout(uiGroupBox);
    uiLayout->setSpacing(12);
    
    animationsCheckBox = new QCheckBox("Enable animations and transitions", uiGroupBox);
    animationsCheckBox->setObjectName("animationsCheckBox");
    animationsCheckBox->setChecked(true);
    uiLayout->addWidget(animationsCheckBox);
    
    tooltipsCheckBox = new QCheckBox("Show detailed tooltips", uiGroupBox);
    tooltipsCheckBox->setObjectName("tooltipsCheckBox");
    tooltipsCheckBox->setChecked(true);
    uiLayout->addWidget(tooltipsCheckBox);
    
    soundEffectsCheckBox = new QCheckBox("Enable sound effects", uiGroupBox);
    soundEffectsCheckBox->setObjectName("soundEffectsCheckBox");
    soundEffectsCheckBox->setChecked(false);
    uiLayout->addWidget(soundEffectsCheckBox);
    
    layout->addWidget(uiGroupBox);
    
    // Add stretch to push content to top
    layout->addStretch();
    
    tabWidget->addTab(appearanceTab, "Appearance");
}

void SettingsDialog::setupAdvancedTab() {
    advancedTab = new QWidget();
    advancedTab->setObjectName("advancedTab");
    
    QVBoxLayout *layout = new QVBoxLayout(advancedTab);
    layout->setSpacing(20);
    layout->setContentsMargins(16, 16, 16, 16);
    
    // Performance group
    performanceGroupBox = new QGroupBox("Performance", advancedTab);
    performanceGroupBox->setObjectName("performanceGroupBox");
    
    QVBoxLayout *perfLayout = new QVBoxLayout(performanceGroupBox);
    perfLayout->setSpacing(12);
    
    hardwareAccelCheckBox = new QCheckBox("Enable hardware acceleration", performanceGroupBox);
    hardwareAccelCheckBox->setObjectName("hardwareAccelCheckBox");
    hardwareAccelCheckBox->setChecked(true);
    perfLayout->addWidget(hardwareAccelCheckBox);
    
    multiThreadCheckBox = new QCheckBox("Use multi-threading for operations", performanceGroupBox);
    multiThreadCheckBox->setObjectName("multiThreadCheckBox");
    multiThreadCheckBox->setChecked(true);
    perfLayout->addWidget(multiThreadCheckBox);
    
    layout->addWidget(performanceGroupBox);
    
    // Security group
    securityGroupBox = new QGroupBox("Security Options", advancedTab);
    securityGroupBox->setObjectName("securityGroupBox");
    
    QVBoxLayout *secLayout = new QVBoxLayout(securityGroupBox);
    secLayout->setSpacing(12);
    
    secureEraseCheckBox = new QCheckBox("Enable cryptographic erasure", securityGroupBox);
    secureEraseCheckBox->setObjectName("secureEraseCheckBox");
    secureEraseCheckBox->setChecked(true);
    secLayout->addWidget(secureEraseCheckBox);
    
    QHBoxLayout *patternsLayout = new QHBoxLayout();
    QLabel *patternsTextLabel = new QLabel("Erase patterns:", securityGroupBox);
    erasePatternsSlider = new QSlider(Qt::Horizontal, securityGroupBox);
    erasePatternsSlider->setObjectName("erasePatternsSlider");
    erasePatternsSlider->setRange(1, 35);
    erasePatternsSlider->setValue(7);
    erasePatternsSlider->setTickPosition(QSlider::TicksBelow);
    erasePatternsSlider->setTickInterval(5);
    
    erasePatternsLabel = new QLabel("7 passes", securityGroupBox);
    erasePatternsLabel->setObjectName("erasePatternsLabel");
    erasePatternsLabel->setMinimumWidth(80);
    
    connect(erasePatternsSlider, &QSlider::valueChanged, [this](int value) {
        erasePatternsLabel->setText(QString("%1 passes").arg(value));
    });
    
    patternsLayout->addWidget(patternsTextLabel);
    patternsLayout->addWidget(erasePatternsSlider);
    patternsLayout->addWidget(erasePatternsLabel);
    secLayout->addLayout(patternsLayout);
    
    layout->addWidget(securityGroupBox);
    
    layout->addStretch();
    
    tabWidget->addTab(advancedTab, "Advanced");
}

void SettingsDialog::setupAboutTab() {
    aboutTab = new QWidget();
    aboutTab->setObjectName("aboutTab");
    
    QVBoxLayout *layout = new QVBoxLayout(aboutTab);
    layout->setSpacing(24);
    layout->setContentsMargins(32, 32, 32, 32);
    layout->setAlignment(Qt::AlignCenter);
    
    // App icon and title
    QLabel *iconLabel = new QLabel(aboutTab);
    iconLabel->setObjectName("appIconLabel");
    iconLabel->setAlignment(Qt::AlignCenter);
    iconLabel->setMinimumHeight(64);
    iconLabel->setText("🗑️"); // Placeholder icon
    iconLabel->setStyleSheet("QLabel { font-size: 48pt; }");
    layout->addWidget(iconLabel);
    
    appInfoLabel = new QLabel("<h1>PurgeX</h1>", aboutTab);
    appInfoLabel->setObjectName("title");
    appInfoLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(appInfoLabel);
    
    versionLabel = new QLabel("Version 1.1", aboutTab);
    versionLabel->setObjectName("subtitle");
    versionLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(versionLabel);
    
    authorLabel = new QLabel("Developed by PurgeX", aboutTab);
    authorLabel->setObjectName("subtitle");
    authorLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(authorLabel);
    
    QLabel *descriptionLabel = new QLabel(
        "PurgeX is a secure data wiping tool that ensures complete data sanitization "
        "through cryptographic erasure and hardware-level security. Built for maximum "
        "security and ease of use.", aboutTab);
    descriptionLabel->setObjectName("descriptionLabel");
    descriptionLabel->setAlignment(Qt::AlignCenter);
    descriptionLabel->setWordWrap(true);
    descriptionLabel->setMaximumWidth(400);
    layout->addWidget(descriptionLabel);
    
    licenseLabel = new QLabel(
        "Licensed under MIT License<br>"
        "Copyright © 2025 PurgeX", aboutTab);
    licenseLabel->setObjectName("subtitle");
    licenseLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(licenseLabel);
    
    layout->addStretch();
    
    tabWidget->addTab(aboutTab, "About");
}

void SettingsDialog::loadCurrentSettings() {
    // Load theme setting
    QSettings settings("PurgeX", "Settings");
    int currentTheme = settings.value("theme/selected", 0).toInt();
    themeComboBox->setCurrentIndex(currentTheme);
    selectedTheme = currentTheme;
    
    // Load other settings from QSettings
    animationsCheckBox->setChecked(settings.value("ui/animations", true).toBool());
    tooltipsCheckBox->setChecked(settings.value("ui/tooltips", true).toBool());
    soundEffectsCheckBox->setChecked(settings.value("ui/sounds", false).toBool());
    
    hardwareAccelCheckBox->setChecked(settings.value("performance/hardwareAccel", true).toBool());
    multiThreadCheckBox->setChecked(settings.value("performance/multiThread", true).toBool());
    
    secureEraseCheckBox->setChecked(settings.value("security/cryptoErase", true).toBool());
    int erasePatterns = settings.value("security/erasePatterns", 7).toInt();
    erasePatternsSlider->setValue(erasePatterns);
    erasePatternsLabel->setText(QString("%1 passes").arg(erasePatterns));
}

void SettingsDialog::onThemeChanged() {
    int index = themeComboBox->currentIndex();
    selectedTheme = index;
    settingsChanged = true;
    applyButton->setEnabled(true);
    updateThemePreview();
}

void SettingsDialog::onThemePreviewClicked() {
    // Simple theme preview without ThemeManager
    QStringList themeNames = QStringList() << "Default Light" << "Professional Dark" << "Pitch Black";
    QString themeName = themeNames.value(selectedTheme, "Default Light");
    
    QMessageBox previewMsg(this);
    previewMsg.setWindowTitle("Theme Preview");
    previewMsg.setText("This is how the " + themeName + " theme looks!");
    previewMsg.setInformativeText("Click OK to continue browsing themes, or Apply to keep this theme.");
    previewMsg.setStandardButtons(QMessageBox::Ok);
    previewMsg.setDefaultButton(QMessageBox::Ok);
    
    previewMsg.exec();
}

void SettingsDialog::updateThemePreview() {
    QStringList themeNames = QStringList() << "Default Light" << "Professional Dark" << "Pitch Black";
    QString themeName = themeNames.value(selectedTheme, "Default Light");
    themePreviewLabel->setText(QString("Preview the %1 theme:").arg(themeName));
}

void SettingsDialog::saveSettings() {
    QSettings settings("PurgeX", "Settings");
    
    // Save theme setting
    settings.setValue("theme/selected", selectedTheme);
    
    // Save UI settings
    settings.setValue("ui/animations", animationsCheckBox->isChecked());
    settings.setValue("ui/tooltips", tooltipsCheckBox->isChecked());
    settings.setValue("ui/sounds", soundEffectsCheckBox->isChecked());
    
    // Save performance settings
    settings.setValue("performance/hardwareAccel", hardwareAccelCheckBox->isChecked());
    settings.setValue("performance/multiThread", multiThreadCheckBox->isChecked());
    
    // Save security settings
    settings.setValue("security/cryptoErase", secureEraseCheckBox->isChecked());
    settings.setValue("security/erasePatterns", erasePatternsSlider->value());
    
    settings.sync();
}

void SettingsDialog::applySettings() {
    // Save all settings
    saveSettings();
    
    // Reset changed flag
    settingsChanged = false;
    applyButton->setEnabled(false);
    
    // Note: Theme application would be handled by parent window if needed
}

void SettingsDialog::onApplyClicked() {
    applySettings();
}

void SettingsDialog::onOkClicked() {
    if (settingsChanged) {
        applySettings();
    }
    accept();
}

void SettingsDialog::onCancelClicked() {
    // Restore original theme if it was changed
    if (settingsChanged) {
        loadCurrentSettings();
    }
    reject();
}

void SettingsDialog::onResetToDefaultsClicked() {
    QMessageBox msgBox(this);
    msgBox.setWindowTitle("Reset Settings");
    msgBox.setText("Reset all settings to their default values?");
    msgBox.setInformativeText("This action cannot be undone.");
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::Cancel);
    msgBox.setDefaultButton(QMessageBox::Cancel);
    
    if (msgBox.exec() == QMessageBox::Yes) {
        resetToDefaults();
    }
}

void SettingsDialog::resetToDefaults() {
    // Reset theme
    themeComboBox->setCurrentIndex(0); // Default theme
    selectedTheme = 0;
    
    // Reset UI options
    animationsCheckBox->setChecked(true);
    tooltipsCheckBox->setChecked(true);
    soundEffectsCheckBox->setChecked(false);
    
    // Reset performance options
    hardwareAccelCheckBox->setChecked(true);
    multiThreadCheckBox->setChecked(true);
    
    // Reset security options
    secureEraseCheckBox->setChecked(true);
    erasePatternsSlider->setValue(7);
    erasePatternsLabel->setText("7 passes");
    
    settingsChanged = true;
    applyButton->setEnabled(true);
}