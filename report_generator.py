from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
import os
from datetime import datetime

def print_report(public_buckets, permissive_policies, open_groups):
    print("\n==== Cloud Security Misconfiguration Report ====\n")
    if public_buckets:
        print("Public S3 Buckets Detected:")
        for bucket in public_buckets:
            print(f" - {bucket}")
    else:
        print("No public S3 buckets found.")
    print("\n---------------------------------\n")
    if permissive_policies:
        print("Overly Permissive IAM Policies:")
        for policy in permissive_policies:
            print(f" - {policy}")
    else:
        print("No overly permissive IAM policies found.")
    print("\n---------------------------------\n")
    if open_groups:
        print("Security Groups Open to the Internet:")
        for group in open_groups:
            print(f" - {group}")
    else:
        print("No open security groups found.")
    print("\n===============================================\n")

def generate_pdf_report(public_buckets, permissive_policies, open_groups, report_folder='report'):
    if not os.path.exists(report_folder):
        os.makedirs(report_folder)
    filename = os.path.join(
        report_folder, f'cloud_security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
    )
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter
    y = height - 50
    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, y, "Cloud Security Misconfiguration Report")
    y -= 40

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Public S3 Buckets:")
    y -= 24
    c.setFont("Helvetica", 12)
    if public_buckets:
        for bucket in public_buckets:
            c.setFillColor(colors.red)
            c.drawString(70, y, f"{bucket}  [MISCONFIGURATION FOUND]")
            c.setFillColor(colors.black)
            y -= 18
    else:
        c.setFillColor(colors.darkgreen)
        c.drawString(70, y, "None found.")
        c.setFillColor(colors.black)
        y -= 18

    y -= 10
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Overly Permissive IAM Policies:")
    y -= 24
    c.setFont("Helvetica", 12)
    if permissive_policies:
        for policy in permissive_policies:
            c.setFillColor(colors.red)
            c.drawString(70, y, f"{policy}  [MISCONFIGURATION FOUND]")
            c.setFillColor(colors.black)
            y -= 18
    else:
        c.setFillColor(colors.darkgreen)
        c.drawString(70, y, "None found.")
        c.setFillColor(colors.black)
        y -= 18

    y -= 10
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Security Groups Open to the Internet:")
    y -= 24
    c.setFont("Helvetica", 12)
    if open_groups:
        for group in open_groups:
            c.setFillColor(colors.red)
            c.drawString(70, y, f"{group}  [MISCONFIGURATION FOUND]")
            c.setFillColor(colors.black)
            y -= 18
    else:
        c.setFillColor(colors.darkgreen)
        c.drawString(70, y, "None found.")
        c.setFillColor(colors.black)
        y -= 18

    c.save()
    print(f"\nPDF report generated: {filename}")
