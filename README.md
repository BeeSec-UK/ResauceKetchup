# ResauceKetchup
ResausceKetchup is a python script that locates cross domain scripts in a page, and checks for a lack of Subresource Integrity. It then outputs the information in a format that can easily be carried over to a Word Document

It is used in Conjucntion with Burpsuite.

To use this script:

1. In Burpsuite, export the issue of "cross domain script include" making sure to untick all the boxes.

2. Save this in an XML format

3. Run the script with the location of your XML as an arguement

  e.g: Python ResauceKetchup.py MyBurpExport.xml

4. it will make a .tsv file that you can then copy and paste into word

5. in word you can convert text to table to get the final product
