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

#include "jucer_Application.h"
#include "jucer_AppearanceSettings.h"


//==============================================================================
AppearanceSettings::AppearanceSettings (const CodeEditorComponent& editor)
    : settings ("COLOUR_SCHEME")
{
    getColourValue ("Background")          = editor.findColour (CodeEditorComponent::backgroundColourId).toString();
    getColourValue ("Line Number Bkgd")    = editor.findColour (CodeEditorComponent::lineNumberBackgroundId).toString();
    getColourValue ("Line Numbers")        = editor.findColour (CodeEditorComponent::lineNumberTextId).toString();
    getColourValue ("Plain Text")          = editor.findColour (CodeEditorComponent::defaultTextColourId).toString();
    getColourValue ("Selected Background") = editor.findColour (CodeEditorComponent::highlightColourId).toString();

    const CodeEditorComponent::ColourScheme cs (editor.getColourScheme());

    for (int i = cs.types.size(); --i >= 0;)
    {
        CodeEditorComponent::ColourScheme::TokenType& t = cs.types.getReference(i);
        getColourValue (t.name) = t.colour.toString();
    }

    Font f (editor.getFont());
    f.setTypefaceName (f.getTypeface()->getName());
    getCodeFontValue() = f.toString();
}

bool AppearanceSettings::readFromXML (const XmlElement& xml)
{
    if (xml.hasTagName (settings.getType().toString()))
    {
        ValueTree newSettings (ValueTree::fromXml (xml));

        for (int i = settings.getNumChildren(); --i >= 0;)
        {
            const ValueTree c (settings.getChild (i));
            if (! newSettings.getChildWithProperty (Ids::name, c.getProperty (Ids::name)).isValid())
                newSettings.addChild (c.createCopy(), 0, nullptr);
        }

        settings = newSettings;
        return true;
    }

    return false;
}

bool AppearanceSettings::readFromFile (const File& file)
{
    const ScopedPointer<XmlElement> xml (XmlDocument::parse (file));
    return xml != nullptr && readFromXML (*xml);
}

bool AppearanceSettings::writeToFile (const File& file) const
{
    const ScopedPointer<XmlElement> xml (settings.createXml());
    return xml != nullptr && xml->writeToFile (file, String::empty);
}

StringArray AppearanceSettings::getColourNames() const
{
    StringArray s;

    for (int i = 0; i < settings.getNumChildren(); ++i)
    {
        const ValueTree c (settings.getChild(i));

        if (c.hasType ("COLOUR"))
            s.add (c [Ids::name]);
    }

    return s;
}

void AppearanceSettings::applyToCodeEditor (CodeEditorComponent& editor) const
{
    CodeEditorComponent::ColourScheme cs (editor.getColourScheme());

    for (int i = cs.types.size(); --i >= 0;)
    {
        CodeEditorComponent::ColourScheme::TokenType& t = cs.types.getReference(i);
        getColour (t.name, t.colour);
    }

    editor.setColourScheme (cs);

    Colour col;
    if (getColour ("Plain Text", col))          editor.setColour (CodeEditorComponent::defaultTextColourId, col);
    if (getColour ("Selected Background", col)) editor.setColour (CodeEditorComponent::highlightColourId, col);
    if (getColour ("Line Number Bkgd", col))    editor.setColour (CodeEditorComponent::lineNumberBackgroundId, col);
    if (getColour ("Line Numbers", col))        editor.setColour (CodeEditorComponent::lineNumberTextId, col);

    if (getColour ("Background", col))
    {
        col = Colours::white.overlaidWith (col);
        editor.setColour (CodeEditorComponent::backgroundColourId, col);
        editor.setColour (CaretComponent::caretColourId, col.contrasting());
    }

    editor.setFont (getCodeFont());
}

Font AppearanceSettings::getCodeFont() const
{
    const String fontString (settings [Ids::font].toString());

    if (fontString.isEmpty())
    {
       #if JUCE_MAC
        Font font (13.0f);
        font.setTypefaceName ("Menlo");
       #else
        Font font (10.0f);
        font.setTypefaceName (Font::getDefaultMonospacedFontName());
       #endif

        return font;
    }

    return Font::fromString (fontString);
}

Value AppearanceSettings::getCodeFontValue()
{
    return settings.getPropertyAsValue (Ids::font, nullptr);
}

Value AppearanceSettings::getColourValue (const String& colourName)
{
    ValueTree c (settings.getChildWithProperty (Ids::name, colourName));

    if (! c.isValid())
    {
        c = ValueTree ("COLOUR");
        c.setProperty (Ids::name, colourName, nullptr);
        settings.addChild (c, -1, nullptr);
    }

    return c.getPropertyAsValue (Ids::colour, nullptr);
}

bool AppearanceSettings::getColour (const String& name, Colour& result) const
{
    const ValueTree colour (settings.getChildWithProperty (Ids::name, name));

    if (colour.isValid())
    {
        result = Colour::fromString (colour [Ids::colour].toString());
        return true;
    }

    return false;
}

//==============================================================================
struct AppearanceEditor
{
    class Window   : public DialogWindow
    {
    public:
        Window()   : DialogWindow ("Appearance Settings", Colours::black, true, true)
        {
            setUsingNativeTitleBar (true);
            setContentOwned (new EditorPanel(), false);
            setResizable (true, true);

            const int width = 350;
            setResizeLimits (width, 200, width, 1000);

            String windowState (getAppProperties().getValue (getWindowPosName()));

            if (windowState.isNotEmpty())
                restoreWindowStateFromString (windowState);
            else
                centreAroundComponent (Component::getCurrentlyFocusedComponent(), width, 500);

            setVisible (true);
        }

        ~Window()
        {
            getAppProperties().setValue (getWindowPosName(), getWindowStateAsString());
        }

        void closeButtonPressed()
        {
            JucerApplication::getApp().appearanceEditorWindow = nullptr;
        }

    private:
        static const char* getWindowPosName()   { return "colourSchemeEditorPos"; }

        JUCE_DECLARE_NON_COPYABLE (Window);
    };

    //==============================================================================
    class EditorPanel  : public Component,
                         private Button::Listener
    {
    public:
        EditorPanel()
            : loadButton ("Load Scheme..."),
              saveButton ("Save Scheme...")
        {
            setOpaque (true);

            rebuildProperties();
            addAndMakeVisible (&panel);

            loadButton.setColour (TextButton::buttonColourId, Colours::grey);
            saveButton.setColour (TextButton::buttonColourId, Colours::grey);

            addAndMakeVisible (&loadButton);
            addAndMakeVisible (&saveButton);

            loadButton.addListener (this);
            saveButton.addListener (this);
        }

        void rebuildProperties()
        {
            AppearanceSettings& scheme = getAppSettings().appearance;

            Array <PropertyComponent*> props;
            Value fontValue (scheme.getCodeFontValue());
            props.add (FontNameValueSource::createProperty  ("Code Editor Font", fontValue));
            props.add (FontSizeValueSource::createProperty  ("Font Size", fontValue));

            const StringArray colourNames (scheme.getColourNames());

            for (int i = 0; i < colourNames.size(); ++i)
                props.add (new ColourPropertyComponent (nullptr, colourNames[i],
                                                        scheme.getColourValue (colourNames[i]),
                                                        Colours::white, false));

            panel.clear();
            panel.addProperties (props);
        }

        void paint (Graphics& g)
        {
            g.fillAll (Colours::black);
        }

        void resized()
        {
            Rectangle<int> r (getLocalBounds());
            panel.setBounds (r.removeFromTop (getHeight() - 26).reduced (4, 3));
            loadButton.setBounds (r.removeFromLeft (getWidth() / 2).reduced (10, 3));
            saveButton.setBounds (r.reduced (10, 3));
        }

    private:
        PropertyPanel panel;
        TextButton loadButton, saveButton;

        void buttonClicked (Button* b)
        {
            if (b == &loadButton)
                loadScheme();
            else
                saveScheme();
        }

        void saveScheme()
        {
            FileChooser fc ("Select a file in which to save this colour-scheme...",
                            getAppSettings().getSchemesFolder().getNonexistentChildFile ("Scheme", ".editorscheme"),
                            "*.editorscheme");

            if (fc.browseForFileToSave (true))
            {
                File file (fc.getResult().withFileExtension (".editorscheme"));
                getAppSettings().appearance.writeToFile (file);
            }
        }

        void loadScheme()
        {
            FileChooser fc ("Please select a colour-scheme file to load...",
                            getAppSettings().getSchemesFolder(),
                            "*.editorscheme");

            if (fc.browseForFileToOpen())
            {
                if (getAppSettings().appearance.readFromFile (fc.getResult()))
                    rebuildProperties();
            }
        }

        JUCE_DECLARE_NON_COPYABLE (EditorPanel);
    };

    //==============================================================================
    class FontNameValueSource   : public ValueSourceFilter
    {
    public:
        FontNameValueSource (const Value& source)  : ValueSourceFilter (source) {}

        var getValue() const
        {
            return Font::fromString (sourceValue.toString()).getTypefaceName();
        }

        void setValue (const var& newValue)
        {
            Font font (Font::fromString (sourceValue.toString()));
            font.setTypefaceName (newValue.toString());
            sourceValue = font.toString();
        }

        static ChoicePropertyComponent* createProperty (const String& title, const Value& value)
        {
            const StringArray& fontNames = getAppSettings().getFontNames();

            Array<var> values;
            for (int i = 0; i < fontNames.size(); ++i)
                values.add (fontNames[i]);

            return new ChoicePropertyComponent (Value (new FontNameValueSource (value)),
                                                title, fontNames, values);
        }
    };

    //==============================================================================
    class FontSizeValueSource   : public ValueSourceFilter
    {
    public:
        FontSizeValueSource (const Value& source)  : ValueSourceFilter (source) {}

        var getValue() const
        {
            return Font::fromString (sourceValue.toString()).getHeight();
        }

        void setValue (const var& newValue)
        {
            sourceValue = Font::fromString (sourceValue.toString()).withHeight (newValue).toString();
        }

        static PropertyComponent* createProperty (const String& title, const Value& value)
        {
            return new SliderPropertyComponent (Value (new FontSizeValueSource (value)),
                                                title, 5.0, 40.0, 0.1, 0.5);
        }
    };
};

Component* AppearanceSettings::createEditorWindow()
{
    return new AppearanceEditor::Window();
}
