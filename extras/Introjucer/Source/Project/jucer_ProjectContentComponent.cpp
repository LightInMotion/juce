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

#include "jucer_ProjectContentComponent.h"
#include "../Application/jucer_MainWindow.h"
#include "../Application/jucer_Application.h"
#include "../Code Editor/jucer_SourceCodeEditor.h"
#include "jucer_ConfigPage.h"
#include "jucer_TreeViewTypes.h"
#include "../Project Saving/jucer_ProjectExporter.h"


//==============================================================================
class FileTreeTab   : public TreePanelBase
{
public:
    FileTreeTab (Project& project)
        : TreePanelBase ("treeViewState_" + project.getProjectUID())
    {
        tree.setMultiSelectEnabled (true);
        setRoot (new GroupTreeViewItem (project.getMainGroup()));
    }
};

//==============================================================================
class ConfigTreeTab   : public TreePanelBase
{
public:
    ConfigTreeTab (Project& project)
        : TreePanelBase ("settingsTreeViewState_" + project.getProjectUID())
    {
        tree.setMultiSelectEnabled (false);
        setRoot (createProjectConfigTreeViewRoot (project));

        if (tree.getNumSelectedItems() == 0)
            tree.getRootItem()->setSelected (true, true);

       #if JUCE_MAC || JUCE_WINDOWS
        addAndMakeVisible (&openProjectButton);
        openProjectButton.setCommandToTrigger (commandManager, CommandIDs::openInIDE, true);
        openProjectButton.setButtonText (commandManager->getNameOfCommand (CommandIDs::openInIDE));

        addAndMakeVisible (&saveAndOpenButton);
        saveAndOpenButton.setCommandToTrigger (commandManager, CommandIDs::saveAndOpenInIDE, true);
        saveAndOpenButton.setButtonText (commandManager->getNameOfCommand (CommandIDs::saveAndOpenInIDE));
       #endif
    }

    void resized()
    {
        Rectangle<int> r (getLocalBounds());
        r.removeFromBottom (6);

        if (saveAndOpenButton.isVisible())
            saveAndOpenButton.setBounds (r.removeFromBottom (28).reduced (20, 3));

        if (openProjectButton.isVisible())
            openProjectButton.setBounds (r.removeFromBottom (28).reduced (20, 3));

        tree.setBounds (r);
    }

    TextButton openProjectButton, saveAndOpenButton;
};

//==============================================================================
ProjectContentComponent::ProjectContentComponent()
    : project (nullptr),
      currentDocument (nullptr),
      treeViewTabs (TabbedButtonBar::TabsAtTop)
{
    setOpaque (true);
    setWantsKeyboardFocus (true);

    treeSizeConstrainer.setMinimumWidth (100);
    treeSizeConstrainer.setMaximumWidth (500);
}

ProjectContentComponent::~ProjectContentComponent()
{
    setProject (nullptr);
    contentView = nullptr;
    removeChildComponent (&bubbleMessage);
    jassert (getNumChildComponents() <= 1);
}

void ProjectContentComponent::paint (Graphics& g)
{
    g.fillAll (Colour::greyLevel (0.8f));
}

void ProjectContentComponent::resized()
{
    Rectangle<int> r (getLocalBounds());

    treeViewTabs.setBounds (r.removeFromLeft (treeViewTabs.getWidth()));

    if (resizerBar != nullptr)
        resizerBar->setBounds (r.removeFromLeft (4));

    if (contentView != nullptr)
        contentView->setBounds (r);
}

void ProjectContentComponent::childBoundsChanged (Component* child)
{
    if (child == &treeViewTabs)
        resized();
}

void ProjectContentComponent::setProject (Project* newProject)
{
    if (project != newProject)
    {
        PropertiesFile& settings = getAppProperties();

        if (project != nullptr)
            project->removeChangeListener (this);

        contentView = nullptr;
        resizerBar = nullptr;

        if (project != nullptr && treeViewTabs.isShowing())
        {
            if (treeViewTabs.getWidth() > 0)
                settings.setValue ("projectTreeviewWidth_" + project->getProjectUID(), treeViewTabs.getWidth());

            settings.setValue ("lastTab_" + project->getProjectUID(), treeViewTabs.getCurrentTabName());
        }

        treeViewTabs.clearTabs();
        project = newProject;

        if (project != nullptr)
        {
            addAndMakeVisible (&treeViewTabs);

            createProjectTabs();

            const String lastTabName (settings.getValue ("lastTab_" + project->getProjectUID()));
            int lastTabIndex = treeViewTabs.getTabNames().indexOf (lastTabName);

            if (lastTabIndex < 0 || lastTabIndex > treeViewTabs.getNumTabs())
                lastTabIndex = 1;

            treeViewTabs.setCurrentTabIndex (lastTabIndex);

            int lastTreeWidth = settings.getValue ("projectTreeviewWidth_" + project->getProjectUID()).getIntValue();
            if (lastTreeWidth < 150)
                lastTreeWidth = 250;

            treeViewTabs.setBounds (0, 0, lastTreeWidth, getHeight());

            addAndMakeVisible (resizerBar = new ResizableEdgeComponent (&treeViewTabs, &treeSizeConstrainer,
                                                                        ResizableEdgeComponent::rightEdge));

            project->addChangeListener (this);

            updateMissingFileStatuses();
            resized();
        }
        else
        {
            treeViewTabs.setVisible (false);
        }
    }
}

void ProjectContentComponent::createProjectTabs()
{
    jassert (project != nullptr);
    treeViewTabs.addTab ("Files",  Colour::greyLevel (0.93f), new FileTreeTab (*project), true);
    treeViewTabs.addTab ("Config", Colour::greyLevel (0.93f), new ConfigTreeTab (*project), true);
}

TreeView* ProjectContentComponent::getFilesTreeView() const
{
    FileTreeTab* ft = dynamic_cast<FileTreeTab*> (treeViewTabs.getTabContentComponent (0));
    return ft != nullptr ? &(ft->tree) : nullptr;
}

ProjectTreeViewBase* ProjectContentComponent::getFilesTreeRoot() const
{
    TreeView* tv = getFilesTreeView();
    return tv != nullptr ? dynamic_cast <ProjectTreeViewBase*> (tv->getRootItem()) : nullptr;
}

void ProjectContentComponent::saveTreeViewState()
{
    for (int i = treeViewTabs.getNumTabs(); --i >= 0;)
    {
        TreePanelBase* t = dynamic_cast<TreePanelBase*> (treeViewTabs.getTabContentComponent (i));

        if (t != nullptr)
            t->saveOpenness();
    }
}

void ProjectContentComponent::saveOpenDocumentList()
{
    if (project != nullptr)
    {
        ScopedPointer<XmlElement> xml (recentDocumentList.createXML());

        if (xml != nullptr)
            getAppProperties().setValue ("lastDocs_" + project->getProjectUID(), xml);
    }
}

void ProjectContentComponent::reloadLastOpenDocuments()
{
    if (project != nullptr)
    {
        ScopedPointer<XmlElement> xml (getAppProperties().getXmlValue ("lastDocs_" + project->getProjectUID()));

        if (xml != nullptr)
        {
            recentDocumentList.restoreFromXML (*project, *xml);
            showDocument (recentDocumentList.getCurrentDocument());
        }
    }
}

void ProjectContentComponent::changeListenerCallback (ChangeBroadcaster*)
{
    updateMissingFileStatuses();
}

void ProjectContentComponent::updateMissingFileStatuses()
{
    ProjectTreeViewBase* p = getFilesTreeRoot();

    if (p != nullptr)
        p->checkFileStatus();
}

bool ProjectContentComponent::showEditorForFile (const File& f)
{
    return getCurrentFile() == f
            || showDocument (JucerApplication::getApp().openDocumentManager.openFile (project, f));
}

File ProjectContentComponent::getCurrentFile() const
{
    return currentDocument != nullptr ? currentDocument->getFile()
                                      : File::nonexistent;
}

bool ProjectContentComponent::showDocument (OpenDocumentManager::Document* doc)
{
    if (doc == nullptr)
        return false;

    if (doc->hasFileBeenModifiedExternally())
        doc->reloadFromFile();

    if (doc == getCurrentDocument() && contentView != nullptr)
    {
        contentView->grabKeyboardFocus();
        return true;
    }

    recentDocumentList.newDocumentOpened (doc);

    return setEditorComponent (doc->createEditor(), doc);
}

void ProjectContentComponent::hideEditor()
{
    currentDocument = nullptr;
    contentView = nullptr;
    updateMainWindowTitle();
    commandManager->commandStatusChanged();
}

void ProjectContentComponent::hideDocument (OpenDocumentManager::Document* doc)
{
    if (doc == currentDocument)
    {
        OpenDocumentManager::Document* replacement = recentDocumentList.getClosestPreviousDocOtherThan (doc);

        if (replacement != nullptr)
            showDocument (replacement);
        else
            hideEditor();
    }
}

bool ProjectContentComponent::setEditorComponent (Component* editor, OpenDocumentManager::Document* doc)
{
    if (editor != nullptr)
    {
        contentView = nullptr;
        contentView = editor;
        currentDocument = doc;
        addAndMakeVisible (editor);
        resized();

        updateMainWindowTitle();
        commandManager->commandStatusChanged();
        editor->grabKeyboardFocus();
        return true;
    }

    updateMainWindowTitle();
    return false;
}

bool ProjectContentComponent::goToPreviousFile()
{
    OpenDocumentManager::Document* currentSourceDoc = recentDocumentList.getCurrentDocument();

    if (currentSourceDoc != nullptr && currentSourceDoc != getCurrentDocument())
        return showDocument (currentSourceDoc);
    else
        return showDocument (recentDocumentList.getPrevious());
}

bool ProjectContentComponent::goToNextFile()
{
    return showDocument (recentDocumentList.getNext());
}

void ProjectContentComponent::updateMainWindowTitle()
{
    MainWindow* mw = findParentComponentOfClass<MainWindow>();

    if (mw != nullptr)
        mw->updateTitle (currentDocument != nullptr ? currentDocument->getName() : String::empty);
}

bool ProjectContentComponent::canProjectBeLaunched() const
{
    if (project != nullptr)
    {
        ScopedPointer <ProjectExporter> launcher (ProjectExporter::createPlatformDefaultExporter (*project));
        return launcher != nullptr;
    }

    return false;
}

ApplicationCommandTarget* ProjectContentComponent::getNextCommandTarget()
{
    return findFirstTargetParentComponent();
}

void ProjectContentComponent::getAllCommands (Array <CommandID>& commands)
{
    const CommandID ids[] = { CommandIDs::saveDocument,
                              CommandIDs::closeDocument,
                              CommandIDs::saveProject,
                              CommandIDs::closeProject,
                              CommandIDs::openInIDE,
                              CommandIDs::saveAndOpenInIDE,
                              CommandIDs::showFilePanel,
                              CommandIDs::showConfigPanel,
                              CommandIDs::goToPreviousDoc,
                              CommandIDs::goToNextDoc,
                              StandardApplicationCommandIDs::del };

    commands.addArray (ids, numElementsInArray (ids));
}

void ProjectContentComponent::getCommandInfo (const CommandID commandID, ApplicationCommandInfo& result)
{
    String documentName;
    if (currentDocument != nullptr)
        documentName = " '" + currentDocument->getName().substring (0, 32) + "'";

    switch (commandID)
    {
    case CommandIDs::saveProject:
        result.setInfo ("Save Project",
                        "Saves the current project",
                        CommandCategories::general, 0);
        result.setActive (project != nullptr);
        break;

    case CommandIDs::closeProject:
        result.setInfo ("Close Project",
                        "Closes the current project",
                        CommandCategories::general, 0);
        result.setActive (project != nullptr);
        break;

    case CommandIDs::saveDocument:
        result.setInfo ("Save" + documentName,
                        "Saves the current document",
                        CommandCategories::general, 0);
        result.setActive (currentDocument != nullptr || project != nullptr);
        result.defaultKeypresses.add (KeyPress ('s', ModifierKeys::commandModifier, 0));
        break;

    case CommandIDs::closeDocument:
        result.setInfo ("Close" + documentName,
                        "Closes the current document",
                        CommandCategories::general, 0);
        result.setActive (currentDocument != nullptr);
       #if JUCE_MAC
        result.defaultKeypresses.add (KeyPress ('w', ModifierKeys::commandModifier | ModifierKeys::ctrlModifier, 0));
       #else
        result.defaultKeypresses.add (KeyPress ('w', ModifierKeys::commandModifier | ModifierKeys::shiftModifier, 0));
       #endif
        break;

    case CommandIDs::goToPreviousDoc:
        result.setInfo ("Previous Document", "Go to previous document", CommandCategories::general, 0);
        result.setActive (recentDocumentList.canGoToPrevious());
       #if JUCE_MAC
        result.defaultKeypresses.add (KeyPress (KeyPress::leftKey, ModifierKeys::commandModifier | ModifierKeys::ctrlModifier, 0));
       #else
        result.defaultKeypresses.add (KeyPress (KeyPress::leftKey, ModifierKeys::ctrlModifier | ModifierKeys::shiftModifier, 0));
       #endif
        break;

    case CommandIDs::goToNextDoc:
        result.setInfo ("Next Document", "Go to next document", CommandCategories::general, 0);
        result.setActive (recentDocumentList.canGoToNext());
       #if JUCE_MAC
        result.defaultKeypresses.add (KeyPress (KeyPress::rightKey, ModifierKeys::commandModifier | ModifierKeys::ctrlModifier, 0));
       #else
        result.defaultKeypresses.add (KeyPress (KeyPress::rightKey, ModifierKeys::ctrlModifier | ModifierKeys::shiftModifier, 0));
       #endif
        break;

    case CommandIDs::openInIDE:
       #if JUCE_MAC
        result.setInfo ("Open in XCode...",
       #elif JUCE_WINDOWS
        result.setInfo ("Open in Visual Studio...",
       #else
        result.setInfo ("Open as a Makefile...",
       #endif
                        "Launches the project in an external IDE",
                        CommandCategories::general, 0);
        result.setActive (canProjectBeLaunched());
        break;

    case CommandIDs::saveAndOpenInIDE:
       #if JUCE_MAC
        result.setInfo ("Save Project and Open in XCode...",
       #elif JUCE_WINDOWS
        result.setInfo ("Save Project and Open in Visual Studio...",
       #else
        result.setInfo ("Save Project and Open as a Makefile...",
       #endif
                        "Saves the project and launches it in an external IDE",
                        CommandCategories::general, 0);
        result.setActive (canProjectBeLaunched());
        result.defaultKeypresses.add (KeyPress ('l', ModifierKeys::commandModifier, 0));
        break;

    case CommandIDs::showFilePanel:
        result.setInfo ("Show File Panel",
                        "Shows the tree of files for this project",
                        CommandCategories::general, 0);
        result.setActive (project != nullptr);
        result.defaultKeypresses.add (KeyPress ('p', ModifierKeys::commandModifier, 0));
        break;

    case CommandIDs::showConfigPanel:
        result.setInfo ("Show Config Panel",
                        "Shows the build options for the project",
                        CommandCategories::general, 0);
        result.setActive (project != nullptr);
        result.defaultKeypresses.add (KeyPress ('i', ModifierKeys::commandModifier, 0));
        break;

    case StandardApplicationCommandIDs::del:
        result.setInfo ("Delete Selected File", String::empty, CommandCategories::general, 0);
        result.defaultKeypresses.add (KeyPress (KeyPress::deleteKey, 0, 0));
        result.defaultKeypresses.add (KeyPress (KeyPress::backspaceKey, 0, 0));
        result.setActive (dynamic_cast<TreePanelBase*> (treeViewTabs.getCurrentContentComponent()) != nullptr);
        break;

    default:
        break;
    }
}

bool ProjectContentComponent::isCommandActive (const CommandID commandID)
{
    return project != nullptr;
}

bool ProjectContentComponent::perform (const InvocationInfo& info)
{
    switch (info.commandID)
    {
    case CommandIDs::saveProject:
        if (project != nullptr && ! reinvokeCommandAfterClosingPropertyEditors (info))
            project->save (true, true);

        break;

    case CommandIDs::closeProject:
        {
            MainWindow* const mw = findParentComponentOfClass<MainWindow>();

            if (mw != nullptr && ! reinvokeCommandAfterClosingPropertyEditors (info))
                mw->closeCurrentProject();
        }

        break;

    case CommandIDs::saveDocument:
        if (! reinvokeCommandAfterClosingPropertyEditors (info))
        {
            if (currentDocument != nullptr)
                currentDocument->save();
            else if (project != nullptr)
                project->save (true, true);
        }

        break;

    case CommandIDs::closeDocument:
        if (currentDocument != nullptr)
            JucerApplication::getApp().openDocumentManager.closeDocument (currentDocument, true);
        break;

    case CommandIDs::goToPreviousDoc:
        goToPreviousFile();
        break;

    case CommandIDs::goToNextDoc:
        goToNextFile();
        break;

    case CommandIDs::openInIDE:
        if (project != nullptr)
        {
            ScopedPointer <ProjectExporter> exporter (ProjectExporter::createPlatformDefaultExporter (*project));

            if (exporter != nullptr)
                exporter->launchProject();
        }
        break;

    case CommandIDs::saveAndOpenInIDE:
        if (project != nullptr)
        {
            if (! reinvokeCommandAfterClosingPropertyEditors (info))
            {
                if (project->save (true, true) == FileBasedDocument::savedOk)
                {
                    ScopedPointer <ProjectExporter> exporter (ProjectExporter::createPlatformDefaultExporter (*project));

                    if (exporter != nullptr)
                        exporter->launchProject();
                }
            }
        }
        break;

    case CommandIDs::showFilePanel:
        treeViewTabs.setCurrentTabIndex (0);
        break;

    case CommandIDs::showConfigPanel:
        treeViewTabs.setCurrentTabIndex (1);
        break;

    case StandardApplicationCommandIDs::del:
        {
            TreePanelBase* const tree = dynamic_cast<TreePanelBase*> (treeViewTabs.getCurrentContentComponent());

            if (tree != nullptr)
                tree->deleteSelectedItems();
        }

        break;

    default:
        return false;
    }

    return true;
}

bool ProjectContentComponent::reinvokeCommandAfterClosingPropertyEditors (const InvocationInfo& info)
{
    if (reinvokeCommandAfterCancellingModalComps (info))
    {
        grabKeyboardFocus(); // to force any open labels to close their text editors
        return true;
    }

    return false;
}

void ProjectContentComponent::showBubbleMessage (const Rectangle<int>& pos, const String& text)
{
    addChildComponent (&bubbleMessage);
    bubbleMessage.setAlwaysOnTop (true);

    bubbleMessage.showAt (pos, AttributedString (text), 3000, true, false);
}
