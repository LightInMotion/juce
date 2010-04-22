/*
  ==============================================================================

   This file is part of the JUCE library - "Jules' Utility Class Extensions"
   Copyright 2004-9 by Raw Material Software Ltd.

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

#include "jucer_ComponentTypeManager.h"
#include "jucer_ComponentTypes.h"

//==============================================================================
class ComponentBoundsEditor  : public PropertyComponent,
                               public ButtonListener,
                               public Value::Listener
{
public:
    enum Type
    {
        left, top, right, bottom
    };

    //==============================================================================
    ComponentBoundsEditor (ComponentDocument& document_, const String& name, Type type_,
                           const ValueTree& compState_, const Value& boundsValue_)
        : PropertyComponent (name, 40), document (document_), type (type_),
          compState (compState_), boundsValue (boundsValue_)
    {
        addAndMakeVisible (label = new Label (String::empty, String::empty));

        label->setEditable (true, true, false);
        label->setColour (Label::backgroundColourId, Colours::white);
        label->setColour (Label::outlineColourId, findColour (ComboBox::outlineColourId));
        label->getTextValue().referTo (Value (new BoundsCoordValueSource (boundsValue, type)));

        addAndMakeVisible (proportionButton = new TextButton ("%"));
        proportionButton->addButtonListener (this);

        addAndMakeVisible (anchorButton1 = new TextButton (String::empty));
        anchorButton1->setConnectedEdges (Button::ConnectedOnLeft | Button::ConnectedOnTop | Button::ConnectedOnRight | Button::ConnectedOnBottom);
        anchorButton1->setTriggeredOnMouseDown (true);
        anchorButton1->addButtonListener (this);

        addAndMakeVisible (anchorButton2 = new TextButton (String::empty));
        anchorButton2->setConnectedEdges (Button::ConnectedOnLeft | Button::ConnectedOnTop | Button::ConnectedOnRight | Button::ConnectedOnBottom);
        anchorButton2->setTriggeredOnMouseDown (true);
        anchorButton2->addButtonListener (this);

        boundsValue.addListener (this);
        valueChanged (boundsValue);
    }

    ~ComponentBoundsEditor()
    {
        boundsValue.removeListener (this);
        deleteAllChildren();
    }

    void resized()
    {
        const Rectangle<int> r (getLookAndFeel().getPropertyComponentContentPosition (*this));

        label->setBounds (r.getX(), r.getY(), r.getWidth() / 2, r.getHeight() / 2);
        proportionButton->setBounds (r.getX() + r.getWidth() / 2, r.getY(),
                                     r.getWidth() / 2, r.getHeight() / 2);

        if (anchorButton2->isVisible())
        {
            anchorButton1->setBounds (r.getX(), r.getY() + r.getHeight() / 2, r.getWidth() / 2, r.getHeight() / 2);
            anchorButton2->setBounds (r.getX() + r.getWidth() / 2, r.getY() + r.getHeight() / 2, r.getWidth() / 2, r.getHeight() / 2);
        }
        else
        {
            anchorButton1->setBounds (r.getX(), r.getY() + r.getHeight() / 2, r.getWidth(), r.getHeight() / 2);
        }
    }

    void refresh()
    {
    }

    void buttonClicked (Button* button)
    {
        RectangleCoordinates r (boundsValue.toString());
        Coordinate& coord = getCoord (r);

        if (button == proportionButton)
        {
            coord.toggleProportionality (document);
            boundsValue = r.toString();
        }
        else if (button == anchorButton1)
        {
            const String marker (pickMarker (anchorButton1, coord.getAnchor1()));

            if (marker.isNotEmpty())
            {
                coord.changeAnchor1 (marker, document);
                boundsValue = r.toString();
            }
        }
        else if (button == anchorButton2)
        {
            const String marker (pickMarker (anchorButton2, coord.getAnchor2()));

            if (marker.isNotEmpty())
            {
                coord.changeAnchor2 (marker, document);
                boundsValue = r.toString();
            }
        }
    }

    void valueChanged (Value&)
    {
        RectangleCoordinates r (boundsValue.toString());
        Coordinate& coord = getCoord (r);

        anchorButton1->setButtonText (coord.getAnchor1());

        anchorButton2->setVisible (coord.isProportional());
        anchorButton2->setButtonText (coord.getAnchor2());
        resized();
    }

    //==============================================================================
    class BoundsCoordValueSource   : public Value::ValueSource,
                                     public Value::Listener
    {
    public:
        BoundsCoordValueSource (const Value& sourceValue_, Type type_)
           : sourceValue (sourceValue_), type (type_)
        {
            sourceValue.addListener (this);
        }

        ~BoundsCoordValueSource() {}

        const var getValue() const
        {
            RectangleCoordinates r (sourceValue.toString());
            Coordinate& coord = getCoord (r);

            if (coord.isProportional())
                return String (coord.getEditableValue()) + "%";

            return coord.getEditableValue();
        }

        void setValue (const var& newValue)
        {
            RectangleCoordinates r (sourceValue.toString());
            Coordinate& coord = getCoord (r);

            coord.setEditableValue ((double) newValue);

            const String newVal (r.toString());
            if (sourceValue != newVal)
                sourceValue = newVal;
        }

        void valueChanged (Value&)
        {
            sendChangeMessage (true);
        }

        //==============================================================================
        juce_UseDebuggingNewOperator

    protected:
        Value sourceValue;
        Type type;

        Coordinate& getCoord (RectangleCoordinates& r) const
        {
            return getCoordForType (type, r);
        }

        BoundsCoordValueSource (const BoundsCoordValueSource&);
        const BoundsCoordValueSource& operator= (const BoundsCoordValueSource&);
    };

    static Coordinate& getCoordForType (const Type type, RectangleCoordinates& r)
    {
        switch (type)
        {
            case left:   return r.left;
            case right:  return r.right;
            case top:    return r.top;
            case bottom: return r.bottom;
            default:     jassertfalse; break;
        }

        return r.left;
    }

    const String pickMarker (TextButton* button, const String& currentMarker)
    {
        RectangleCoordinates b (boundsValue.toString());

        PopupMenu m;
        document.getComponentMarkerMenuItems (compState, getTypeName(),
                                              getCoord (b), m, button == anchorButton1);

        const int r = m.showAt (button);

        if (r > 0)
            return document.getChosenMarkerMenuItem (compState, getCoord (b), r);

        return String::empty;
    }

private:
    ComponentDocument& document;
    Type type;
    ValueTree compState;
    Value boundsValue;
    Label* label;
    TextButton* proportionButton;
    TextButton* anchorButton1;
    TextButton* anchorButton2;

    Coordinate& getCoord (RectangleCoordinates& r)
    {
        return getCoordForType (type, r);
    }

    const String getTypeName() const
    {
        switch (type)
        {
            case left:      return "left";
            case right:     return "right";
            case top:       return "top";
            case bottom:    return "bottom";
            default:        jassertfalse; break;
        }

        return String::empty;
    }
};


//==============================================================================
ComponentTypeHandler::ComponentTypeHandler (const String& name_, const String& xmlTag_,
                                            const String& memberNameRoot_)
    : name (name_), xmlTag (xmlTag_),
      memberNameRoot (memberNameRoot_)
{
}

ComponentTypeHandler::~ComponentTypeHandler()
{
}

Value ComponentTypeHandler::getValue (const var::identifier& name, ValueTree& state, ComponentDocument& document) const
{
    return state.getPropertyAsValue (name, document.getUndoManager());
}

void ComponentTypeHandler::updateComponent (ComponentDocument& document, Component* comp, const ValueTree& state)
{
    RectangleCoordinates pos (state [ComponentDocument::compBoundsProperty].toString());
    comp->setBounds (pos.resolve (document));

    comp->setName (state [ComponentDocument::compNameProperty]);
}

void ComponentTypeHandler::initialiseNewItem (ComponentDocument& document, ValueTree& state)
{
    state.setProperty (ComponentDocument::compNameProperty, String::empty, 0);
    state.setProperty (ComponentDocument::memberNameProperty, document.getNonExistentMemberName (getMemberNameRoot()), 0);

    const Rectangle<int> bounds (getDefaultSize().withPosition (Point<int> (Random::getSystemRandom().nextInt (100) + 100,
                                                                            Random::getSystemRandom().nextInt (100) + 100)));

    state.setProperty (ComponentDocument::compBoundsProperty, RectangleCoordinates (bounds, state [ComponentDocument::memberNameProperty]).toString(), 0);
}


//==============================================================================
class CompMemberNameValueSource   : public Value::ValueSource,
                                    public Value::Listener
{
public:
    CompMemberNameValueSource (ComponentDocument& document_, const ValueTree& state_)
       : sourceValue (state_.getPropertyAsValue (ComponentDocument::memberNameProperty, document_.getUndoManager())),
         document (document_),
         state (state_)
    {
        sourceValue.addListener (this);
    }

    ~CompMemberNameValueSource() {}

    void valueChanged (Value&)      { sendChangeMessage (true); }
    const var getValue() const   { return sourceValue.toString(); }

    void setValue (const var& newValue)
    {
        String newVal (newValue.toString());

        //xxx check for uniqueness + rename any coords that use the name..


        newVal = makeValidCppIdentifier (newVal, false, true, false);

        if (sourceValue != newVal)
            sourceValue = newVal;
    }

private:
    Value sourceValue;
    ComponentDocument& document;
    ValueTree state;

    CompMemberNameValueSource (const CompMemberNameValueSource&);
    const CompMemberNameValueSource& operator= (const CompMemberNameValueSource&);
};

void ComponentTypeHandler::createPropertyEditors (ComponentDocument& document, ValueTree& state, Array <PropertyComponent*>& props)
{
    props.add (new TextPropertyComponent (Value (new CompMemberNameValueSource (document, state)), "Member Name", 256, false));

    props.add (new ComponentBoundsEditor (document, "Left",   ComponentBoundsEditor::left,   state, getValue (ComponentDocument::compBoundsProperty, state, document)));
    props.add (new ComponentBoundsEditor (document, "Right",  ComponentBoundsEditor::right,  state, getValue (ComponentDocument::compBoundsProperty, state, document)));
    props.add (new ComponentBoundsEditor (document, "Top",    ComponentBoundsEditor::top,    state, getValue (ComponentDocument::compBoundsProperty, state, document)));
    props.add (new ComponentBoundsEditor (document, "Bottom", ComponentBoundsEditor::bottom, state, getValue (ComponentDocument::compBoundsProperty, state, document)));
}

//==============================================================================
ComponentTypeManager::ComponentTypeManager()
{
    #define ADD_TO_LIST(HandlerType)   handlers.add (new HandlerType());
    #include "jucer_ComponentTypes.h"
    #undef ADD_TO_LIST
}

ComponentTypeManager::~ComponentTypeManager()
{
}

Component* ComponentTypeManager::createFromStoredType (ComponentDocument& document, const ValueTree& value)
{
    ComponentTypeHandler* handler = getHandlerFor (value.getType());
    if (handler == 0)
        return 0;

    Component* c = handler->createComponent();
    if (c != 0)
        handler->updateComponent (document, c, value);

    return c;
}

ComponentTypeHandler* ComponentTypeManager::getHandlerFor (const String& type)
{
    for (int i = handlers.size(); --i >= 0;)
        if (handlers.getUnchecked(i)->getXmlTag() == type)
            return handlers.getUnchecked(i);

    return 0;
}

const StringArray ComponentTypeManager::getTypeNames() const
{
    StringArray s;
    for (int i = 0; i < handlers.size(); ++i)
        s.add (handlers.getUnchecked(i)->getName());

    return s;
}

juce_ImplementSingleton_SingleThreaded (ComponentTypeManager);