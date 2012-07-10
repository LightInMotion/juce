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

#ifndef __JUCER_PROJECTCONTENTCOMPONENT_JUCEHEADER__
#define __JUCER_PROJECTCONTENTCOMPONENT_JUCEHEADER__

#include "jucer_Project.h"
#include "../Application/jucer_OpenDocumentManager.h"
class ProjectTreeViewBase;

//==============================================================================
/**
*/
class ProjectContentComponent  : public Component,
                                 public ApplicationCommandTarget,
                                 private ChangeListener
{
public:
    //==============================================================================
    ProjectContentComponent();
    ~ProjectContentComponent();

    Project* getProject() const noexcept    { return project; }
    virtual void setProject (Project* project);

    void saveTreeViewState();
    void saveOpenDocumentList();
    void reloadLastOpenDocuments();

    bool showEditorForFile (const File& f);
    File getCurrentFile() const;

    bool showDocument (OpenDocumentManager::Document* doc);
    void hideDocument (OpenDocumentManager::Document* doc);
    OpenDocumentManager::Document* getCurrentDocument() const   { return currentDocument; }

    void hideEditor();
    bool setEditorComponent (Component* editor, OpenDocumentManager::Document* doc);
    Component* getEditorComponent() const                       { return contentView; }

    bool goToPreviousFile();
    bool goToNextFile();

    void updateMissingFileStatuses();
    virtual void createProjectTabs();

    void showBubbleMessage (const Rectangle<int>& pos, const String& text);

    //==============================================================================
    ApplicationCommandTarget* getNextCommandTarget();
    void getAllCommands (Array <CommandID>& commands);
    void getCommandInfo (CommandID commandID, ApplicationCommandInfo& result);
    bool isCommandActive (const CommandID commandID);
    bool perform (const InvocationInfo& info);

    void paint (Graphics& g);
    void resized();
    void childBoundsChanged (Component* child);

protected:
    Project* project;
    OpenDocumentManager::Document* currentDocument;
    RecentDocumentList recentDocumentList;

    TabbedComponent treeViewTabs;
    ScopedPointer<ResizableEdgeComponent> resizerBar;
    ScopedPointer<Component> contentView;

    ComponentBoundsConstrainer treeSizeConstrainer;
    BubbleMessageComponent bubbleMessage;

    void changeListenerCallback (ChangeBroadcaster*);
    void updateMainWindowTitle();
    bool reinvokeCommandAfterClosingPropertyEditors (const InvocationInfo&);
    bool canProjectBeLaunched() const;
    TreeView* getFilesTreeView() const;
    ProjectTreeViewBase* getFilesTreeRoot() const;

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR (ProjectContentComponent);
};


#endif   // __JUCER_PROJECTCONTENTCOMPONENT_JUCEHEADER__
