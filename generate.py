# Generates PDF file with VSS report
# NOTE: DO NOT modify the file unless you are aware of the changes because of reportlab PDF

import argparse
import logging
import textwrap
import datetime


from reportlab.pdfgen import canvas
from reportlab.graphics.charts.piecharts import Pie
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import A4, LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm, cm
from reportlab.platypus import *
from reportlab.rl_config import defaultPageSize
from reportlab.lib.colors import HexColor
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.doughnut import *
from reportlab.graphics.charts.barcharts import *
from reportlab.graphics.charts.linecharts import *
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.charts.textlabels import Label
from reportlab.platypus.tableofcontents import TableOfContents
from math import floor, ceil
from xml.sax.saxutils import escape
from reportlab.lib.validators import Auto

from gather_info import *

from logging.config import dictConfig
from logging.handlers import SysLogHandler

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

fields = []
styles = getSampleStyleSheet()
ParaStyle = styles["Normal"]
styleN = styles["BodyText"]
WIDTH = defaultPageSize[0]
HEIGHT = defaultPageSize[1]
Config_file_name = ""


#CommonData adds page number and header to every page at the footer on bottom right corner
class CommonData(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        canvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        """add page info to each page (page x of y)"""
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            self.add_logo()
            if(self._pageNumber != 1):
                self.drawString(5, HEIGHT-70, "VSS - Security Overview Report")
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        self.setFont("Helvetica", 10)
        if(self._pageNumber != 1):
            self.drawRightString(200*mm, 10*mm,
                "Page %d of %d" % (self._pageNumber, page_count))
    
    def add_logo(self):
        self.drawImage("images/vmware_logo.jpg", 20*mm, 10*mm, width=1.0*inch, height=0.16*inch)


# Add VSS image on the first page. Can be replaced with custom image by providing the file in same location.
# Try to use a ".jpeg" image
def on_first_page(canvas, doc):
    canvas.saveState()
    canvas.drawImage("images/vss.jpeg", 20*mm, HEIGHT-200,width=6.5*inch, height=1.06*inch)
    canvas.setFont('Times-Bold', 20)
    canvas.drawCentredString(WIDTH/2.0, HEIGHT - 350, "Security Overview Report")
    canvas.setFont('Times-Roman', 14)
    company = get_org_name()
    canvas.drawCentredString(WIDTH/2.0, HEIGHT/2.0-(100), "For: " + company)
    canvas.setFillColor(HexColor("#696969"))
    canvas.setFont('Times-Roman', 12)
    today = datetime.date.today()
    time_formatted =  datetime.datetime.utcnow().replace(microsecond=0).strftime("%b-%d-%Y %H:%M:%S UTC")
    today_formatted = today.strftime("%b-%d-%Y")
    canvas.drawCentredString(WIDTH/2.0, HEIGHT/2.0-(120), "Generated On: " + time_formatted)
    canvas.restoreState()
 
## Adds Paragraph and keeps the section together       
def add_para(txt, style=ParaStyle, klass=Paragraph, sep=0.1):
    s = Spacer(0, sep*inch)
    para = klass(txt, style)
    sect = [s, para]
    result = KeepTogether(sect)
    return result

    
def add_compliance_risk_overview():
    frame_aws_cis = Frame(doc.leftMargin, doc.topMargin+270, doc.width/2-6, doc.height/2-30, id='doughnut1', showBoundary=0)
    frame_azure_cis = Frame(doc.leftMargin+doc.width/2+6, doc.rightMargin+270, doc.width/2-6,
                doc.height/2-30, id='doughtnut2', showBoundary=0)
    fields.append(NextPageTemplate("TwoDonuts"))
    fields.append(FrameBreak())
    fields.append(KeepInFrame(doc.width/2, doc.height/2, add_aws_cis_doughnut_chart(), mode='shrink'))

    return frame_aws_cis, frame_azure_cis
         

def add_top_10_objects_by_risk():
    columns = ["Risk\nScore", "Finding\nCount", "Object Name", "Object ID", "Provider", "Cloud Account"]    
    data = get_top_10_objects_by_risk()
    
    # Use escape to add escape characters 
    for d in data:
        d[2] = Paragraph(escape(d[2]), style = styles["BodyText"])
        d[3] = Paragraph(escape(d[3]), style = styles["BodyText"])
        d[5] = Paragraph(escape(d[5]), style = styles["BodyText"])

    data.insert(0, columns)
    rs_table = Table(data, [60,45,90,170,60,80], 80, repeatRows=1)
    rs_table.hAlign = "CENTER"
    rs_table.vAlign = "MIDDLE"
    rs_table.setStyle(TableStyle([   
                       ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                       ('VALIGN', (0,0), (-1,0), 'MIDDLE'),
                       ('VALIGN', (0,1), (-1,-1), 'TOP'),
                       ('FONT', (0,0), (-1,-1), 'Helvetica')]))
    
    data_len = len(data)

    for each in range(data_len):
        if each % 2 == 0:
            bg_color = colors.whitesmoke #HexColor("#DCDCDC") 
        else:
            bg_color = colors.white
        rs_table.setStyle(TableStyle([('BACKGROUND', (0, each), (-1, each), bg_color)]))
    
    rs_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), HexColor("#3a7c91"))]))
    rs_table.setStyle(TableStyle([('TEXTCOLOR', (0, 0), (-1, 0), colors.white)]))
    fields.append(rs_table)
    

def add_asset_risk_overview():
    fields.append(add_para("<br></br><br></br>"))
    fields.append(Paragraph("5.3 Asset Risk Overview", style=styles["Heading3"]))
    fields.append(add_para("Table: List of objects with the highest risk score. Shows the objects with the highest risk."))
   #fields.append(add_para("There are 1872 assets out of 15072 assets that have violations across 92 accounts."))
    fields.append(add_para("<br></br><br></br>"))    
    add_top_10_objects_by_risk()
    
def add_trends_open_findings_chart():
    drawing = Drawing(300,200)
    
    data, months = get_open_findings_trends()
    maxVal = max(data[0])
    
    if(maxVal > 1000):
        multiplier = 1000
        step = 4 * multiplier
    else:
        multiplier = 100
        step = 4 * multiplier
    
    value_step = int(ceil(maxVal/step))*multiplier
    
    if(value_step < 10):
        value_step = 1
    
    lc = HorizontalLineChart()
    lc.x = 25
    lc.y = 40
    lc.height = 100
    lc.width = doc.width
    lc.lines.symbol = makeMarker('Square')
    lc.joinedLines = 1
    lc.data = data
    lc.categoryAxis.categoryNames = months
    lc.categoryAxis.labels.boxAnchor = 'c'
    # lc.categoryAxis.valueMin = months[0]
    lc.valueAxis.valueMin = 0
    lc.valueAxis.valueStep = value_step
    lc.valueAxis.valueMax = max(data[0])*2
    lc.lines[0].strokeColor = colors.green
    #lc.fillColor = colors.whitesmoke
    #lc.inFill = 1
    #lc.categoryAxis.labels.dx = -20
    #lc.categoryAxis.labels.dy = -10
    lc.lineLabelFormat = "%d"
    
    
    chartLabel = Label()
    chartLabel.setText("Trends - Total Open Findings")
    chartLabel.fontSize = 10
    chartLabel.fillColor = HexColor("#737373")
    chartLabel.fontName = 'Helvetica-Bold'
    
    chartLabel.dx = 250
    chartLabel.dy = 160
    
    drawing.add(chartLabel)
    drawing.add(lc)
    fields.append(drawing)

def add_trends_new_resolved_findings_chart():
    drawing = Drawing(200,200)
    
    data, month = get_new_resolved_trends()
    
    max_val_new_findings = max(data[0])
    max_val_resolved_findings = max(data[1])
    
    maxVal = max(max_val_new_findings, max_val_resolved_findings)
    
    if(maxVal > 1000):
        multiplier = 1000
        step = 4 * multiplier
    else:
        multiplier = 100
        step = 4 * multiplier
    
    value_step = int(ceil(maxVal/step))*multiplier
    
    if(value_step < 10):
        value_step = 1
    
    bar = VerticalBarChart()
    bar.x = 25
    bar.y = -35
    bar.height = 100
    bar.width = doc.width
    bar.barWidth = 2
    bar.data = data
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = int(maxVal * 2) ## graph displa twice as much as max violation
    bar.valueAxis.valueStep =  value_step ## Convert to neartest step
    bar.categoryAxis.categoryNames = month
    bar.bars[0].strokeColor = None
    bar.bars[1].strokeColor = None
    bar.bars[0].fillColor = HexColor("#E57300")
    bar.bars[1].fillColor = HexColor("#408F00")
    
    chartLabel = Label()
    chartLabel.setText("Trends - New Findings")
    chartLabel.fontSize = 10
    chartLabel.fillColor = HexColor("#737373")
    chartLabel.fontName = 'Helvetica-Bold'
    chartLabel.dx = 250
    chartLabel.dy = 90
    
    legend = Legend()
    legend.alignment = 'right'
    legend.colorNamePairs = [[HexColor("#E57300"), "New Findings"], [HexColor("#408F00"), "Resolved Findings"]]
    legend.columnMaximum = 2
    legend.x = 400
    legend.y = 120    
    
    drawing.add(legend)
    drawing.add(chartLabel)
    drawing.add(bar)
    fields.append(drawing)
    
    
# Adds Executive summary section
def add_executive_summary_section():
    
    exec_summary_title_frame = Frame(doc.leftMargin, doc.height+40, doc.width, 50, id='exec summary', showBoundary=0)
    intro_frame = Frame(doc.leftMargin, doc.height-80, doc.width, 150, id="introduction frame", showBoundary=0)
    scope_frame = Frame(doc.leftMargin, doc.height-210, doc.width, 130, id='scope frame', showBoundary=0)
    progress_title_frame = Frame(doc.leftMargin, doc.height-240, doc.width, 50, id='progress summary', showBoundary=0)
    trend_frame_1 = Frame(doc.leftMargin, doc.height/2-120, doc.width, 250, id='open finding chart', showBoundary=0)
    trend_frame_2 = Frame(doc.leftMargin, doc.height/2-240, doc.width, 250, id='new resolved chart', showBoundary=0)
    
    fields.append(NextPageTemplate("ExecutiveSummary"))
    fields.append(FrameBreak())
    fields.append(add_para("Executive Summary", style=styles["Heading1"]))
    fields.append(FrameBreak())
    fields.append(add_para("1. Introduction", style=styles["Heading2"]))
    account_info = get_account_info()
    text = '''This report contains cloud configuration security assessment results from ''' + str(account_info["accounts"]) + ''' cloud accounts across your environment. 
    The cloud environment was evaluated across ''' + str(account_info["rules"]) + ''' rules associated with ''' + str(account_info["compliance_frameworks"]) + ''' compliance frameworks. 
    There were ''' + str(account_info["total_violations"]) + ''' violations found.<br/><br/> 
    
    This analysis provides summaries and breakdowns to help address the risk identified, along with change comparison since last evaluation. 
    The findings are generated by comprehensive evaluation through a revolutionary inter-connected security model that identifies in-depth configuration problems.'''
    
    info = add_para(text)
    fields.append(info)
    fields.append(FrameBreak())
    fields.append(add_scope_section())
    fields.append(FrameBreak())
    fields.append(add_para("3. Progress", style=styles["Heading2"]))
    fields.append(FrameBreak())
    fields.append(KeepInFrame(doc.width, 250, add_trends_open_findings_chart(), mode='shrink'))
    fields.append(FrameBreak())
    fields.append(KeepInFrame(doc.width, 250, add_trends_new_resolved_findings_chart(), mode='shrink'))
    return exec_summary_title_frame, intro_frame, scope_frame, progress_title_frame, trend_frame_1, trend_frame_2

def add_scope_section():
    fields.append(Paragraph("2. Scope", style=styles["Heading2"]))
    config = get_config()["config"]
    
    text = '''
    The scope of this report is within the context of the following filters:<br/>
    Provider: ''' + str(config["providers"]) + '''<br/>
    Cloud Accounts: ''' + str(config["cloudAccountIds"]) + '''<br/>
    Frameworks: ''' + str(get_account_info()["compliance_frameworks"]) + '''<br/>
    Severity: ''' + str(config["severity"])+ '''<br/>
    Cloud Tags: ''' + str(config["cloudTags"]) + '''<br/>
    Environment:	All<br/>
    '''
    # text = '''
    #  The scope of this report is within the context of the following filters:<br/>
    # ''' + str(config)
        
    info = add_para(text)
    fields.append(info)


def add_findings_by_provider_chart():
    drawing = Drawing(300, 200)
    data = get_findings_by_provider()
    maxVal = max(data[0])
    
    if(maxVal > 1000):
        multiplier = 1000
        step = 4 * multiplier
    else:
        multiplier = 100
        step = 4 * multiplier
    
    value_step = int(ceil(maxVal/step))*multiplier
    
    if(value_step < 10):
        value_step = 10
    
    bar = HorizontalBarChart()
    bar.x = 30
    bar.y = 0
    bar.height = 100
    bar.width = 400
    bar.data = data
    bar.strokeColor = colors.white
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = maxVal*2   ## graph displa twice as much as max violation
    bar.valueAxis.valueStep = value_step ## Convert to neartest 100
    bar.categoryAxis.labels.boxAnchor = 'ne'
    bar.categoryAxis.labels.dx = -10
    bar.categoryAxis.labels.dy = -2
    bar.categoryAxis.labels.fontName = 'Helvetica'
    bar.categoryAxis.categoryNames = ["AWS", "Azure"]
    bar.bars[(0,0)].fillColor = HexColor("#434476")
    bar.bars[(0,1)].fillColor = HexColor("#B170DB")
    bar.barWidth = 3.5
    bar.barSpacing = 0.1
    bar.barLabelFormat = '%d'
    bar.barLabels.nudge = 15
    bar.bars[0].strokeColor = None

    drawing.add(bar)
  #  add_legend(drawing, bar)
    yLabel = Label()
    yLabel.setText("Number of Findings")
    yLabel.fontSize = 10
    yLabel.fontName = 'Helvetica'
    yLabel.dx = 250
    yLabel.dy = -30
    
    chartLabel = Label()
    chartLabel.setText("Findings by Provider")
    chartLabel.fontSize = 10
    chartLabel.fillColor = HexColor("#737373")
    chartLabel.fontName = 'Helvetica-Bold'
    chartLabel.dx = 250
    chartLabel.dy = 160
    
    drawing.add(chartLabel)
    drawing.add(yLabel)
    fields.append(drawing)


# Page 3
def add_table_cloud_accounts():
    data = [("Cloud Accounts", get_account_info()["accounts"])]
    
    tb = Table(data, 110,30)
    tb.setStyle(TableStyle([
              ('FONT', (0,0), (-1,-1), 'Helvetica')]))

    
    for each in range(len(data)):
        if each % 2 == 0:
            bg_color = colors.whitesmoke
        else:
            bg_color = colors.white

        tb.setStyle(TableStyle([('BACKGROUND', (0, each), (-1, each), bg_color)]))
    fields.append(tb)

# Page 3
def add_table_findings_summary():
    data = [("Open Findings", get_open_resolved_findings()["open"]), ("Resolved Findings", get_open_resolved_findings()["resolved"]),\
            ("Rules Configured", get_account_info()["rules"]), ("Suppressed Findings", get_account_info()["suppressed_findings"])]
    
    tb = Table(data, 110,30)
    tb.setStyle(TableStyle([
              ('FONT', (0,0), (-1,-1), 'Helvetica')]))
            
    for each in range(len(data)):
        if each % 2 == 0:
            bg_color = colors.whitesmoke
        else:
            bg_color = colors.white

        tb.setStyle(TableStyle([('BACKGROUND', (0, each), (-1, each), bg_color)]))
    fields.append(tb)
    

def add_table_summary_violations_frameworks():
    aws_violations, azure_violations = get_all_violations_by_severity()
    compliance_frameworks = ("Compliance Frameworks", get_account_info()["compliance_frameworks"])

    configuration = get_config()
    severity_level = configuration["config"]["severity"]
    
    data = []
    for level in severity_level:
        if(level.lower() == "high"):
            high = aws_violations[0]+azure_violations[0]
            temp = ("High Severity", high)
            data.append(temp)
        if(level.lower() == "medium"):
            medium = aws_violations[1]+azure_violations[1]
            temp = ("Medium Severity", medium)
            data.append(temp)
        if(level.lower() == "low"):
            low = aws_violations[2]+azure_violations[2]
            temp = ("Low Severity", low)
            data.append(temp)
    
    data.append(compliance_frameworks)
    tb = Table(data, 120, 30)
    tb.hAlign = "CENTER"
    tb.vAlign = "MIDDLE"
    tb.setStyle(TableStyle([   
                       #('BACKGROUND', (-1,0), (-1, -1), HexColor("#3498eb")),
                       #('GRID',(0,0),(-1,-1),0.01*inch,(0,0,0,)),
                       ('FONT', (0,0), (-1,-1), 'Helvetica')]))
    
    for each in range(len(data)):
        if each % 2 == 0:
            bg_color = colors.white
        else:
            bg_color = colors.whitesmoke

        tb.setStyle(TableStyle([('BACKGROUND', (0, each), (-1, each), bg_color)]))
    fields.append(tb)
    
# Page 3
def add_cloud_security_overview_section():

    title_frame = Frame(doc.leftMargin, doc.height, doc.width, 80, id='cloud security title', showBoundary=0)
    account_frame = Frame(doc.leftMargin, doc.height-20, doc.width/2-6, 50, id="cloud accounts", showBoundary=0)
    violations_summary_frame = Frame(doc.leftMargin+doc.width/2+6, doc.height-120, doc.width/2-6, 150, id="violations summary", showBoundary=0)
    findings_summary_frame = Frame(doc.leftMargin, doc.height-170, doc.width/2-6, 150, id="findings summary", showBoundary=0)
    provider_findings_frame  = Frame(doc.leftMargin, doc.height/2-110, doc.width, 250, id='provider chart', showBoundary=0)
    
    fields.append(NextPageTemplate("CloudSecurityOverview"))
    fields.append(FrameBreak())
    fields.append(Paragraph("4. Cloud Security Overview", style=styles["Heading2"]))
    fields.append(FrameBreak())
    fields.append(KeepInFrame(doc.width/2-6, doc.height/2-30, add_table_cloud_accounts(), mode='shrink'))
    fields.append(FrameBreak())
    fields.append(KeepInFrame(doc.width/2-6, doc.height/2-30, add_table_summary_violations_frameworks(), mode='shrink'))
    fields.append(FrameBreak())
    fields.append(KeepInFrame(doc.width/2-6, 150, add_table_findings_summary(), mode='shrink'))
    fields.append(FrameBreak())
    fields.append(KeepInFrame(doc.width/2-6, doc.height/2, add_findings_by_provider_chart(), mode='shrink'))
    fields.append(FrameBreak())
    return title_frame, account_frame, violations_summary_frame, findings_summary_frame, provider_findings_frame

def add_top_10_rules():
    data = get_top_10_rules()
    columns = ["Rule", "Provider", "Object Type", "Severity", "Count"]
    for d in data:
        d[0] = Paragraph(d[0], style = styles["BodyText"])   
    data.insert(0, columns)
    tb = Table(data, [170,60,80,80,60], 45, repeatRows=1)
    tb.hAlign = "CENTER"
    tb.vAlign = "MIDDLE"
    tb.setStyle(TableStyle([
                       ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                       ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                       #('GRID',(0,0),(-1,-1),0.01*inch,(0,0,0,)),
                       ('FONT', (0,0), (-1,-1), 'Helvetica')]))
    
    data_len = len(data)

    for each in range(data_len):
        if each % 2 == 0:
            bg_color =  colors.white #HexColor("#edf3f3") 
        else:
            bg_color = colors.whitesmoke
        tb.setStyle(TableStyle([('BACKGROUND', (0, each), (-1, each), bg_color)]))
    
    tb.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), HexColor("#3a7c91"))]))
    tb.setStyle(TableStyle([('TEXTCOLOR', (0, 0), (-1, 0), colors.white)]))
    fields.append(tb)
    if(len(data) < 6):
        fields.append(FrameBreak())

def add_top_10_accounts_by_open_findings():
    result = add_para("Table: Top 10 Accounts by Open Findings")
    fields.append(result)
    fields.append(add_para("<br></br>"))
    sectionTable = Table([["Provider", "Cloud Account", "Open Findings", "Suppressed\nFindings", "Resolved\nFindings"]], [70,170,120,70,70], 35)
    sectionTable.setStyle(TableStyle([   
                       ('BACKGROUND', (0,0), (-1, -1), HexColor("#3a7c91")),
                       ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                       ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                       ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                       ('FONTSIZE', (0,0), (-1,-1), 12),
                       ('FONT', (0,0), (-1,-1), 'Helvetica')]))
    
    data = get_high_med_low_top_10_violations()
    columns = ["", "", "High", "Medium", "Low", "", ""]
    for d in data:
        # Added to support word wrap for account IDs
        # In case of Azure, the subscription ID is long
        d[1] = Paragraph(d[1], style = styles["BodyText"])

    data.insert(0, columns)
    accountsTable = Table(data, [70,170,40,45,35,70, 70], 35)

    accountsTable.setStyle(TableStyle([   
                       ('BACKGROUND', (0,0), (-1, 0), HexColor("#3a7c91")),    
                       #('SPAN', (0,0), (1,0)),
                       ('TEXTCOLOR', (2,0), (2,-1), colors.red),
                       ('TEXTCOLOR', (3,0), (3,-1), colors.darkorange),
                       ('TEXTCOLOR', (4,0), (4,-1), colors.orange),
                       ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                       ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                       ('FONTSIZE', (0,0), (-1,-1), 10),
                       ('FONT', (0,0), (-1,-1), 'Helvetica')]))
    
    data_len = len(data)
    for each in range(data_len):
        if each % 2 == 0:
            bg_color = colors.whitesmoke
        else:
            bg_color = colors.white

        accountsTable.setStyle(TableStyle([('BACKGROUND', (0, each), (-1, each), bg_color)]))
     
    finalTable = Table([[sectionTable], [accountsTable]], 440)
    finalTable.setStyle(TableStyle([   
                       ('SPAN',(0,0),(-1,0)),
                       ('ALIGN', (0,0), (-1,-1), 'CENTER'),            
                       ('FONTSIZE', (0,0), (-1,-1), 10),
                       ('FONT', (0,0), (-1,-1), 'Helvetica')]))

    fields.append(finalTable)

def add_azure_findings_by_severity_chart():
    drawing = Drawing(doc.width/2-18, doc.height/2-45)
    aws, azure  = get_all_violations_by_severity()
    rules = [azure]
    
    maxVal = max(rules[0])
    
    if(maxVal > 1000):
        multiplier = 1000
        step = 4 * multiplier
    else:
        multiplier = 100
        step = 4 * multiplier
    
    value_step = int(ceil(maxVal/step))*multiplier
    
    if(value_step < 10):
        value_step = 1
    
    
    bar = VerticalBarChart()
    bar.x = 10
    bar.y = 70
    bar.height = doc.height/4
    bar.width = doc.width/2 - 40
    bar.barWidth = 2
    bar.barSpacing = 0.5
    bar.data = rules
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = int(maxVal* 1.5) ## graph displa twice as much as max violation
    bar.valueAxis.valueStep = value_step ## Convert to neartest 10
    bar.categoryAxis.categoryNames = ["high", "medium", "low"]
    bar.barLabelFormat = '%d'
    bar.barLabels.nudge = 15
    bar.bars[0].fillColor = HexColor("#B170DB")
    bar.bars[0].strokeColor = None
    bar.categoryAxis.labels.boxAnchor = 'n'
    
    chartLabel = Label()
    chartLabel.setText("Findings by Severity - Azure")
    chartLabel.fontSize = 10
    chartLabel.fontName = 'Helvetica-Bold'
    chartLabel.fillColor = HexColor("#737373")
    chartLabel.dx = doc.rightMargin
    chartLabel.dy = doc.height-80
    
    
    drawing.add(chartLabel)
    drawing.add(bar)
    fields.append(drawing) 
    

def add_aws_findings_by_severity_chart():
    drawing = Drawing(doc.width/2-18, doc.height/2-45)
    aws, azure  = get_all_violations_by_severity()
    rules = [aws]
    
    maxVal = max(rules[0])
    
    if(maxVal > 1000):
        multiplier = 1000
        step = 4 * multiplier
    else:
        multiplier = 100
        step = 4 * multiplier
    
    value_step = int(ceil(maxVal/step))*multiplier
    
    if(value_step < 10):
        value_step = 1
        
        
    bar = VerticalBarChart()
    bar.x = 10
    bar.y = 70
    bar.height = doc.height/4
    bar.width = doc.width/2 - 40
    bar.barWidth = 2
    bar.barSpacing = 0.5
    bar.data = rules
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = int(maxVal*1.5) ## graph displa twice as much as max violation
    bar.valueAxis.valueStep = value_step ## Convert to neartest 10
    bar.categoryAxis.categoryNames = ["high", "medium", "low"]
    bar.barLabelFormat = '%d'
    bar.barLabels.nudge = 15
    bar.bars[0].fillColor = HexColor("#434476")
    bar.bars[0].strokeColor = None
    bar.categoryAxis.labels.boxAnchor = 'n'
    drawing.add(bar)
    fields.append(drawing)

def add_rule_violations_by_provider_chart(doc):

    frame1 = Frame(doc.leftMargin, doc.height, doc.width, 90, id='summary', showBoundary=0)
    frame2 = Frame(doc.leftMargin, doc.height-70, doc.width/2-40, 50, id='aws logo', showBoundary=0)
    frame3 = Frame(doc.leftMargin+doc.width/2+6, doc.height-70, doc.width/2-40, 50, id='azure logo', showBoundary=0)
    frame4 = Frame(doc.leftMargin, doc.topMargin+270, doc.width/2-6, doc.height/2-30, id='aws chart', showBoundary=0)
    frame5 = Frame(doc.leftMargin+doc.width/2+6, doc.rightMargin+270, doc.width/2-6, doc.height/2-30, id='azure chart', showBoundary=0)
    frame6 = Frame(doc.leftMargin, doc.height/2-260, 480, 300, id='top 10 rule table', showBoundary=0)
    
    fields.append(NextPageTemplate('RuleRiskOverview'))
    fields.append(FrameBreak())
    fields.append(Paragraph("5.2 Rule Risk Overview", style=styles["Heading3"]))
    fields.append(add_para("A prioritized list of rule violations by cloud account. Shows the rule violations with the highest risk."))
    text = "There are " + str(get_open_resolved_findings()["open"]) + " open findings after evaluating "+ str(get_account_info()["rules"]) + " rules across AWS and Azure."
    fields.append(add_para(text))
    fields.append(FrameBreak())
    aws_logo = Image("images/aws-logo.jpg", width=30, height=30, hAlign='RIGHT')
    fields.append(KeepTogether(aws_logo))
    fields.append(FrameBreak())
    azure_logo = Image("images/azure-logo.jpg", width=30, height=30, hAlign='RIGHT')
    fields.append(KeepTogether(azure_logo))
    fields.append(FrameBreak())
    fields.append(KeepInFrame(doc.width/2-6, doc.height/2-30,add_aws_findings_by_severity_chart(), mode='shrink'))
    fields.append(FrameBreak())
    fields.append(KeepInFrame(doc.width/2-6, doc.height/2, add_azure_findings_by_severity_chart(), mode='shrink'))
    fields.append(FrameBreak())
    fields.append(KeepInFrame(doc.width/2-6, doc.height/2, add_top_10_rules(), mode='shrink'))
    return frame1, frame2, frame3, frame4, frame5, frame6

def add_cloud_account_risk_overview_section():
    fields.append(Paragraph("5. Risk Overview", style=styles["Heading2"]))
    fields.append(Paragraph("5.1 Cloud Account Risk Overview", style=styles["Heading3"]))
    open_resolve = get_open_resolved_findings()
    account_info = get_account_info()
    text = ''' There are ''' + str(open_resolve["open"]) + ''' open findings and ''' + str(open_resolve["resolved"]) + ''' resolved findings across ''' + str(account_info["accounts"]) + ''' accounts.
    '''
    fields.append(add_para(text))
    add_findings_by_account_chart()
    add_top_10_accounts_by_open_findings()


# Page 4
def add_findings_by_account_chart():
    drawing = Drawing(500, 500)
    open_findings, _ , accounts = get_top_10_accounts_by_findings()
    length_accounts = len(accounts)

    for account in accounts:
        if(length_accounts > 0):
            idx = accounts.index(account)
            long_account_string = account
            if(len(long_account_string)>15):
                accounts.remove(account)
                account = textwrap.fill(account, 15)
                accounts.insert(idx,account)
            length_accounts = length_accounts - 1

    maxVal = max(open_findings[0]) ## Find maximum number of findings open or resolved and use it as basis for plotting the graph
    
    if(maxVal > 1000):
        multiplier = 1000
        step = 4 * multiplier
    else:
        multiplier = 100
        step = 4 * multiplier
    
    value_step = int(ceil(maxVal/step))*multiplier
    
    if(value_step < 10):
        value_step = 1
    
    bar = HorizontalBarChart()
    bar.x = 25
    bar.y = -25
    bar.height = 500
    bar.width = 450
    bar.data = open_findings
    #bar.strokeColor = colors.white
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = maxVal*2  ## graph display 2 times as much as max violation
    bar.valueAxis.valueStep = value_step  ## Convert to neartest 100
    bar.categoryAxis.labels.boxAnchor = 'ne'
    bar.categoryAxis.labels.dx = -10
    bar.categoryAxis.labels.dy = 0
    bar.categoryAxis.labels.fontName = 'Helvetica'
    bar.categoryAxis.categoryNames = accounts
    bar.bars[0].fillColor = HexColor("#E57300")
    bar.barWidth = 2.5
    bar.categoryAxis.strokeWidth = 0
    bar.barLabelFormat = '%d'
    bar.barLabels.nudge = 15
    bar.barLabels.fillColor = colors.black
    bar.bars[0].strokeColor = None
    
    legend = Legend()
    legend.alignment = 'right'
    legend.colorNamePairs = [[HexColor("#E57300"), "Open Findings"]]
    legend.columnMaximum = 2
    legend.x = 400
    legend.y = 470
    
    drawing.add(legend)
    
    drawing.add(bar)
    fields.append(drawing)
    newPage()
    
def newPage():
    fields.append(PageBreak())

# Creates the initial report document
def init_report(report_name):
    doc = SimpleDocTemplate(report_name, pagesize=LETTER)
    return doc

def build_report(document):
    document.build(fields, canvasmaker=CommonData)
    logging.info("Successfully generated report !!\n")


def parse_arguments():
    parser = argparse.ArgumentParser(usage="Provide configuration file name with --config param and report file name with --output-file")
    required_group = parser.add_argument_group('required arguments')
    required_group.add_argument('--config', help="configuration file name in json format ex: config.json", required=True)
    required_group.add_argument('--output-file', help="output file name ex: vss_report.pdf", required=True)
    args = parser.parse_args()
    
    config_file_name = args.config
    report_file_name = args.output_file
    return config_file_name, report_file_name


if __name__ == '__main__':
    
    logging.getLogger().setLevel(logging.INFO)
    
    Config_file_name, report_file_name = parse_arguments()
    
    logging.info("\nGenerating Report ...\n")
    auth()
    gather_data()
    doc = init_report(report_file_name)  
    frameFirstPage = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id='normal')
    exec_summary_frame, intro_frame, scope_frame, progress_title_frame, trend_frame_1, trend_frame_2 = add_executive_summary_section()
    
    title_frame, account_frame, violations_summary_frame, findings_summary_frame, provider_findings_frame = add_cloud_security_overview_section()
    add_cloud_account_risk_overview_section()
    
    # This is for Rule Risk Overview 
    frame1, frame2, frame3, frame4, frame5, frame6 = add_rule_violations_by_provider_chart(doc)
    doc.addPageTemplates([PageTemplate(id='OneCol', frames=[frameFirstPage], onPage=on_first_page),
                      PageTemplate(id='RuleRiskOverview',frames=[frame1, frame2, frame3, frame4, frame5, frame6]),
                      PageTemplate(id='CloudSecurityOverview', frames=[title_frame, account_frame, violations_summary_frame, findings_summary_frame, provider_findings_frame]),
                      PageTemplate(id='ExecutiveSummary', frames=[exec_summary_frame, intro_frame, scope_frame, progress_title_frame,trend_frame_1, trend_frame_2])
                      ])
    
    add_asset_risk_overview()
    
    build_report(doc)