/*
  ==============================================================================

   This file is part of the JUCE library - "Jules' Utility Class Extensions"
   Copyright 2004-11 by Raw Material Software Ltd.

  ------------------------------------------------------------------------------

   JUCE can be redistributed and/or modified under the terms of the GNU General
   Public License (Version 2), as published by the Free Software Foundation.
   A copy of the license is included in the JUCE distribution, or can be found
   online at www.gnu.org/licenses.

   JUCE is distributed in the hope that it will be useful, but WITHOUT ANY
   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
   A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

  ------------------------------------------------------------------------------

   To release a closed-source product which uses JUCE, commercial licenses are
   available: visit www.rawmaterialsoftware.com/juce for more information.

  ==============================================================================
*/

#ifndef __JUCER_APPLICATION_JUCEHEADER__
#define __JUCER_APPLICATION_JUCEHEADER__

#include "../jucer_Headers.h"
#include "jucer_MainWindow.h"
#include "jucer_JuceUpdater.h"
#include "jucer_CommandLine.h"
#include "../Code Editor/jucer_SourceCodeEditor.h"


//==============================================================================
class JucerApplication   : public JUCEApplication
{
public:
    //==============================================================================
    JucerApplication() {}
    ~JucerApplication() {}

    //==============================================================================
    void initialise (const String& commandLine)
    {
        if (commandLine.isNotEmpty())
        {
            const int appReturnCode = performCommandLine (commandLine);

            if (appReturnCode != commandLineNotPerformed)
            {
                setApplicationReturnValue (appReturnCode);
                quit();
                return;
            }
        }

        commandManager = new ApplicationCommandManager();
        commandManager->registerAllCommandsForTarget (this);

        menuModel = new MainMenuModel();

        doExtraInitialisation();

        ImageCache::setCacheTimeout (30 * 1000);

        if (commandLine.trim().isNotEmpty() && ! commandLine.trim().startsWithChar ('-'))
            anotherInstanceStarted (commandLine);
        else
            mainWindowList.reopenLastProjects();

        makeSureUserHasSelectedModuleFolder();

        mainWindowList.createWindowIfNoneAreOpen();

       #if JUCE_MAC
        MenuBarModel::setMacMainMenu (menuModel);
       #endif
    }

    void shutdown()
    {
        appearanceEditorWindow = nullptr;

       #if JUCE_MAC
        MenuBarModel::setMacMainMenu (nullptr);
       #endif
        menuModel = nullptr;

        mainWindowList.forceCloseAllWindows();
        openDocumentManager.clear();
        commandManager = nullptr;
        settings.flush();
    }

    //==============================================================================
    void systemRequestedQuit()
    {
        if (cancelAnyModalComponents())
        {
            new AsyncQuitRetrier();
            return;
        }

        if (mainWindowList.askAllWindowsToClose())
            quit();
    }

    //==============================================================================
    const String getApplicationName()
    {
        return String (ProjectInfo::projectName) + " " + getApplicationVersion();
    }

    const String getApplicationVersion()
    {
        return ProjectInfo::versionString;
    }

    bool moreThanOneInstanceAllowed()
    {
       #ifndef JUCE_LINUX
        return false;
       #else
        return true; //xxx should be false but doesn't work on linux..
       #endif
    }

    void anotherInstanceStarted (const String& commandLine)
    {
        openFile (commandLine.unquoted());
    }

    static JucerApplication& getApp()
    {
        JucerApplication* const app = dynamic_cast<JucerApplication*> (JUCEApplication::getInstance());
        jassert (app != nullptr);
        return *app;
    }

    //==============================================================================
    class MainMenuModel  : public MenuBarModel
    {
    public:
        MainMenuModel()
        {
            setApplicationCommandManagerToWatch (commandManager);
        }

        StringArray getMenuBarNames()
        {
            return getApp().getMenuNames();
        }

        PopupMenu getMenuForIndex (int /*topLevelMenuIndex*/, const String& menuName)
        {
            PopupMenu menu;
            getApp().createMenu (menu, menuName);
            return menu;
        }

        void menuItemSelected (int menuItemID, int /*topLevelMenuIndex*/)
        {
            if (menuItemID >= 100 && menuItemID < 200)
            {
                // open a file from the "recent files" menu
                getApp().openFile (getAppSettings().recentFiles.getFile (menuItemID - 100));
            }
            else if (menuItemID >= 300 && menuItemID < 400)
            {
                OpenDocumentManager::Document* doc = getApp().openDocumentManager.getOpenDocument (menuItemID - 300);
                jassert (doc != nullptr);

                getApp().mainWindowList.openDocument (doc);
            }
        }
    };

    virtual StringArray getMenuNames()
    {
        const char* const names[] = { "File", "Edit", "View", "Window", "Tools", nullptr };
        return StringArray (names);
    }

    virtual void createMenu (PopupMenu& menu, const String& menuName)
    {
        if (menuName == "File")         createFileMenu   (menu);
        else if (menuName == "Edit")    createEditMenu   (menu);
        else if (menuName == "View")    createViewMenu   (menu);
        else if (menuName == "Window")  createWindowMenu (menu);
        else if (menuName == "Tools")   createToolsMenu  (menu);
        else                            jassertfalse; // names have changed?
    }

    virtual void createFileMenu (PopupMenu& menu)
    {
        menu.addCommandItem (commandManager, CommandIDs::newProject);
        menu.addSeparator();
        menu.addCommandItem (commandManager, CommandIDs::open);

        PopupMenu recentFiles;
        getAppSettings().recentFiles.createPopupMenuItems (recentFiles, 100, true, true);
        menu.addSubMenu ("Open recent file", recentFiles);

        menu.addSeparator();
        menu.addCommandItem (commandManager, CommandIDs::closeDocument);
        menu.addCommandItem (commandManager, CommandIDs::saveDocument);
        menu.addSeparator();
        menu.addCommandItem (commandManager, CommandIDs::closeProject);
        menu.addCommandItem (commandManager, CommandIDs::saveProject);
        menu.addSeparator();
        menu.addCommandItem (commandManager, CommandIDs::openInIDE);
        menu.addCommandItem (commandManager, CommandIDs::saveAndOpenInIDE);

        #if ! JUCE_MAC
          menu.addSeparator();
          menu.addCommandItem (commandManager, StandardApplicationCommandIDs::quit);
        #endif
    }

    virtual void createEditMenu (PopupMenu& menu)
    {
        menu.addCommandItem (commandManager, StandardApplicationCommandIDs::undo);
        menu.addCommandItem (commandManager, StandardApplicationCommandIDs::redo);
        menu.addSeparator();
        menu.addCommandItem (commandManager, StandardApplicationCommandIDs::cut);
        menu.addCommandItem (commandManager, StandardApplicationCommandIDs::copy);
        menu.addCommandItem (commandManager, StandardApplicationCommandIDs::paste);
        menu.addCommandItem (commandManager, StandardApplicationCommandIDs::del);
        menu.addCommandItem (commandManager, StandardApplicationCommandIDs::selectAll);
        menu.addCommandItem (commandManager, StandardApplicationCommandIDs::deselectAll);
        menu.addSeparator();
        menu.addCommandItem (commandManager, CommandIDs::toFront);
        menu.addCommandItem (commandManager, CommandIDs::toBack);
        menu.addSeparator();
        menu.addCommandItem (commandManager, CommandIDs::group);
        menu.addCommandItem (commandManager, CommandIDs::ungroup);
        menu.addSeparator();
        menu.addCommandItem (commandManager, CommandIDs::bringBackLostItems);
    }

    virtual void createViewMenu (PopupMenu& menu)
    {
        menu.addCommandItem (commandManager, CommandIDs::showFilePanel);
        menu.addCommandItem (commandManager, CommandIDs::showConfigPanel);
        menu.addSeparator();
        menu.addCommandItem (commandManager, CommandIDs::showAppearanceSettings);
    }

    virtual void createWindowMenu (PopupMenu& menu)
    {
        menu.addCommandItem (commandManager, CommandIDs::closeWindow);
        menu.addSeparator();

        menu.addCommandItem (commandManager, CommandIDs::goToPreviousDoc);
        menu.addCommandItem (commandManager, CommandIDs::goToNextDoc);
        menu.addSeparator();

        const int numDocs = jmin (50, getApp().openDocumentManager.getNumOpenDocuments());

        for (int i = 0; i < numDocs; ++i)
        {
            OpenDocumentManager::Document* doc = getApp().openDocumentManager.getOpenDocument(i);

            menu.addItem (300 + i, doc->getName());
        }

        menu.addSeparator();
        menu.addCommandItem (commandManager, CommandIDs::closeAllDocuments);
    }

    virtual void createToolsMenu (PopupMenu& menu)
    {
        menu.addCommandItem (commandManager, CommandIDs::updateModules);
        menu.addCommandItem (commandManager, CommandIDs::showUTF8Tool);
    }

    //==============================================================================
    void getAllCommands (Array <CommandID>& commands)
    {
        JUCEApplication::getAllCommands (commands);

        const CommandID ids[] = { CommandIDs::newProject,
                                  CommandIDs::open,
                                  CommandIDs::showPrefs,
                                  CommandIDs::closeAllDocuments,
                                  CommandIDs::saveAll,
                                  CommandIDs::updateModules,
                                  CommandIDs::showAppearanceSettings,
                                  CommandIDs::showUTF8Tool };

        commands.addArray (ids, numElementsInArray (ids));
    }

    void getCommandInfo (CommandID commandID, ApplicationCommandInfo& result)
    {
        switch (commandID)
        {
        case CommandIDs::newProject:
            result.setInfo ("New Project...", "Creates a new Jucer project", CommandCategories::general, 0);
            result.defaultKeypresses.add (KeyPress ('n', ModifierKeys::commandModifier, 0));
            break;

        case CommandIDs::open:
            result.setInfo ("Open...", "Opens a Jucer project", CommandCategories::general, 0);
            result.defaultKeypresses.add (KeyPress ('o', ModifierKeys::commandModifier, 0));
            break;

        case CommandIDs::showPrefs:
            result.setInfo ("Preferences...", "Shows the preferences panel.", CommandCategories::general, 0);
            result.defaultKeypresses.add (KeyPress (',', ModifierKeys::commandModifier, 0));
            break;

        case CommandIDs::showAppearanceSettings:
            result.setInfo ("Fonts and Colours...", "Shows the appearance settings window.", CommandCategories::general, 0);
            break;

        case CommandIDs::closeAllDocuments:
            result.setInfo ("Close All Documents", "Closes all open documents", CommandCategories::general, 0);
            result.setActive (openDocumentManager.getNumOpenDocuments() > 0);
            break;

        case CommandIDs::saveAll:
            result.setInfo ("Save All", "Saves all open documents", CommandCategories::general, 0);
            result.setActive (openDocumentManager.anyFilesNeedSaving());
            break;

        case CommandIDs::updateModules:
            result.setInfo ("Download the latest JUCE modules", "Checks online for any JUCE modules updates and installs them", CommandCategories::general, 0);
            break;

        case CommandIDs::showUTF8Tool:
            result.setInfo ("UTF-8 String-Literal Helper", "Shows the UTF-8 string literal utility", CommandCategories::general, 0);
            break;

        default:
            JUCEApplication::getCommandInfo (commandID, result);
            break;
        }
    }

    bool perform (const InvocationInfo& info)
    {
        switch (info.commandID)
        {
            case CommandIDs::newProject:                createNewProject(); break;
            case CommandIDs::open:                      askUserToOpenFile(); break;
            case CommandIDs::showPrefs:                 showPrefsPanel(); break;
            case CommandIDs::saveAll:                   openDocumentManager.saveAll(); break;
            case CommandIDs::closeAllDocuments:         closeAllDocuments (true); break;
            case CommandIDs::showUTF8Tool:              showUTF8ToolWindow(); break;
            case CommandIDs::showAppearanceSettings:    showAppearanceEditorWindow(); break;
            case CommandIDs::updateModules:             runModuleUpdate (String::empty); break;
            default:                                    return JUCEApplication::perform (info);
        }

        return true;
    }

    //==============================================================================
    void showPrefsPanel()
    {
        jassertfalse;
    }

    void createNewProject()
    {
        if (makeSureUserHasSelectedModuleFolder())
        {
            MainWindow* mw = mainWindowList.getOrCreateEmptyWindow();
            mw->showNewProjectWizard();
            mainWindowList.avoidSuperimposedWindows (mw);
        }
    }

    void askUserToOpenFile()
    {
        FileChooser fc ("Open File");

        if (fc.browseForFileToOpen())
            openFile (fc.getResult());
    }

    bool openFile (const File& file)
    {
        return mainWindowList.openFile (file);
    }

    bool closeAllDocuments (bool askUserToSave)
    {
        return openDocumentManager.closeAll (askUserToSave);
    }

    bool makeSureUserHasSelectedModuleFolder()
    {
        if (! ModuleList::isLocalModulesFolderValid())
        {
            if (! runModuleUpdate ("Please select a location to store your local set of JUCE modules,\n"
                                   "and download the ones that you'd like to use!"))
            {
                AlertWindow::showMessageBox (AlertWindow::WarningIcon,
                                             "Introjucer",
                                             "Unless you create a local JUCE folder containing some modules, you'll be unable to save any projects correctly!\n\n"
                                             "Use the option on the 'Tools' menu to set this up!");

                return false;
            }
        }

        return true;
    }

    bool runModuleUpdate (const String& message)
    {
        ModuleList list;
        list.rescan (ModuleList::getDefaultModulesFolder (nullptr));
        JuceUpdater::show (list, mainWindowList.windows[0], message);

        ModuleList::setLocalModulesFolder (list.getModulesFolder());
        return ModuleList::isJuceOrModulesFolder (list.getModulesFolder());
    }

    void showAppearanceEditorWindow()
    {
        if (appearanceEditorWindow == nullptr)
            appearanceEditorWindow = AppearanceSettings::createEditorWindow();

        appearanceEditorWindow->toFront (true);
    }

    //==============================================================================
    virtual void doExtraInitialisation() {}
    virtual void addExtraConfigItems (Project&, TreeViewItem&) {}

    virtual Component* createProjectContentComponent() const
    {
        return new ProjectContentComponent();
    }

    //==============================================================================
    StoredSettings settings;
    Icons icons;

    ScopedPointer<MainMenuModel> menuModel;

    MainWindowList mainWindowList;
    OpenDocumentManager openDocumentManager;

    ScopedPointer<Component> appearanceEditorWindow;

private:
    class AsyncQuitRetrier  : public Timer
    {
    public:
        AsyncQuitRetrier()   { startTimer (500); }

        void timerCallback()
        {
            stopTimer();
            delete this;

            JUCEApplication* app = JUCEApplication::getInstance();
            if (app != nullptr)
                app->systemRequestedQuit();
        }

        JUCE_DECLARE_NON_COPYABLE (AsyncQuitRetrier);
    };
};


#endif   // __JUCER_APPLICATION_JUCEHEADER__
