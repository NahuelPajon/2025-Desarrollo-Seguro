// src/services/invoiceService.ts
import db from '../db';
import { Invoice } from '../types/invoice';
import axios from 'axios';
import { promises as fs } from 'fs';
import * as path from 'path';

interface InvoiceRow {
  id: string;
  userId: string;
  amount: number;
  dueDate: Date;
  status: string;
}

class InvoiceService {
  static async list( userId: string, status?: string, operator?: string ): Promise<Invoice[]> {
    let q = db<InvoiceRow>('invoices').where({ userId: userId });

    const allowedOperators = ['eq', 'ne'];
    const allowedStatuses = ['paid', 'unpaid'];

    if (operator && !allowedOperators.includes(operator)) {
      throw new Error('Invalid operator');
    }
    if (status && !allowedStatuses.includes(status)) {
      throw new Error('Invalid status');
    }

    if (operator && status) {
      q = q.andWhereRaw(` status ${operator} '${status}'`)
    }

    const rows = await q.select();
    const invoices = rows.map(row => ({
      id: row.id,
      userId: row.userId,
      amount: row.amount,
      dueDate: row.dueDate,
      status: row.status} as Invoice
    ));
    return invoices;
  }

  static async setPaymentCard(
    userId: string,
    invoiceId: string,
    paymentBrand: string,
    ccNumber: string,
    ccv: string,
    expirationDate: string
  ) {
    // use axios to call http://paymentBrand/payments as a POST request
    // with the body containing ccNumber, ccv, expirationDate
    // and handle the response accordingly
    const paymentBrands = {
      'visa': 'http://visa',
      'master': 'http://master',
      'amex': 'http://amex'
    } //Asumimos que estos son los servicios de pago que tenemos

    const paymentUrl = paymentBrands[paymentBrand];

    if (!paymentUrl) {
      throw new Error('Invalid payment brand');
    }

    const paymentResponse = await axios.post(`${paymentUrl}/payments`, {
      ccNumber,
      ccv,
      expirationDate
    });
    if (paymentResponse.status !== 200) {
      throw new Error('Payment failed');
    }

    // Update the invoice status in the database
    await db('invoices')
      .where({ id: invoiceId, userId })
      .update({ status: 'paid' });
    };
  static async getInvoice( invoiceId:string, userId: string): Promise<Invoice> {
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId, userId: userId }).first();
    if (!invoice) {
      throw new Error('Invoice not found');
    }
    return invoice as Invoice;
  }


  static async getReceipt(
    invoiceId: string,
    pdfName: string,
    userId: string
  ) {
    // check if the invoice exists
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId, userId: userId }).first();
    if (!invoice) {
      throw new Error('Invoice not found');
    }
    try {
      const baseDir = '/invoices';
      const fileName = path.basename(pdfName); // Aseguramos que el nombre del archivo sea el mismo que el que se pasa
      const filePath = path.join(baseDir, fileName); // Aseguramos que el archivo se encuentre en el directorio correcto

      const content = await fs.readFile(filePath, 'utf-8');
      return content;
    } catch (error) {
      // send the error to the standard output
      console.error('Error reading receipt file:', error);
      throw new Error('Receipt not found');

    }
  };

};

export default InvoiceService;
