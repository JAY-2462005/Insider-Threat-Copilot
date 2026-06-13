"""
Reusable chart components for the Insider Threat Copilot frontend.
"""

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd


def create_risk_gauge(risk_score: float) -> go.Figure:
    """Create a gauge chart for risk score visualization."""
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=risk_score,
        title={'text': "Risk Score"},
        delta={'reference': 50},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 30], 'color': "lightgreen"},
                {'range': [30, 50], 'color': "yellow"},
                {'range': [50, 70], 'color': "orange"},
                {'range': [70, 100], 'color': "red"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 70
            }
        }
    ))
    return fig


def create_timeline_chart(df: pd.DataFrame) -> go.Figure:
    """Create a timeline chart showing risk scores over time."""
    df_sorted = df.sort_values('timestamp')
    
    fig = px.scatter(
        df_sorted,
        x='timestamp',
        y='risk_score',
        color='severity',
        size='rowcount',
        hover_data=['username', 'data_asset'],
        title='Risk Score Timeline',
        labels={'timestamp': 'Date/Time', 'risk_score': 'Risk Score'}
    )
    
    return fig


def create_heatmap(data: dict) -> go.Figure:
    """Create a heatmap showing patterns in the data."""
    z_data = list(data.values())
    x_labels = list(data.keys())
    
    fig = go.Figure(data=go.Heatmap(
        z=[z_data],
        x=x_labels,
        colorscale='RdYlGn_r'
    ))
    
    fig.update_layout(
        title='Risk Pattern Heatmap',
        xaxis_title='Pattern',
        yaxis_title='Frequency'
    )
    
    return fig


def create_sankey_diagram(users: list, departments: list, destinations: list) -> go.Figure:
    """Create a Sankey diagram showing data flow patterns."""
    fig = go.Figure(data=[go.Sankey(
        node=dict(
            pad=15,
            line=dict(color='black', width=0.5),
            label=users + departments + destinations
        ),
        link=dict(
            source=[0, 1, 0],  # indices correspond to labels
            target=[1, 2, 2],
            value=[8, 4, 2]
        )
    )])
    
    fig.update_layout(title_text="Data Access Flow", font_size=10)
    
    return fig


def create_comparison_chart(metric_name: str, data: dict) -> go.Figure:
    """Create a comparison bar chart."""
    fig = px.bar(
        x=list(data.keys()),
        y=list(data.values()),
        title=f'{metric_name} Comparison',
        labels={'x': metric_name, 'y': 'Count'}
    )
    
    return fig
