import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'package:qr_code_scanner_plus/qr_code_scanner_plus.dart';
import 'package:url_launcher/url_launcher.dart';

void main() => runApp(const MyApp());

class MyApp extends StatelessWidget {
  const MyApp({Key? key}) : super(key: key);
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: ThemeData(primarySwatch: Colors.blueGrey),
      home: const QRViewExample(),
    );
  }
}

class QRViewExample extends StatefulWidget {
  const QRViewExample({Key? key}) : super(key: key);
  @override
  State<StatefulWidget> createState() => _QRViewExampleState();
}

class _QRViewExampleState extends State<QRViewExample> {
  final GlobalKey qrKey = GlobalKey(debugLabel: 'QR');
  Barcode? result;
  QRViewController? controller;

  @override
  void reassemble() {
    super.reassemble();
    controller!.pauseCamera();
    controller!.resumeCamera();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('QR Safe Scanner')),
      body: Column(
        children: <Widget>[
          Expanded(
            flex: 4,
            child: _buildQrView(context),
          ),
          Expanded(
            flex: 1,
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: <Widget>[
                if (result != null)
                  Text('Result: ${result!.code}')
                else
                  const Text('Scan a code'),
                ElevatedButton(
                  onPressed: result != null && result!.code != null
                      ? () => _checkWithVirusTotal(result!.code!)
                      : null,
                  child: const Text('Check with VirusTotal'),
                ),
              ],
            ),
          )
        ],
      ),
    );
  }

  Widget _buildQrView(BuildContext context) {
    return QRView(
      key: qrKey,
      onQRViewCreated: _onQRViewCreated,
      overlay: QrScannerOverlayShape(
        borderColor: Colors.white,
        borderRadius: 10,
        borderLength: 30,
        borderWidth: 10,
        cutOutSize: MediaQuery.of(context).size.width * 0.8,
      ),
    );
  }

  void _onQRViewCreated(QRViewController controller) {
    setState(() {
      this.controller = controller;
    });
    controller.scannedDataStream.listen((scanData) {
      setState(() {
        result = scanData;
      });
    });
  }

  void _showErrorDialog(String message, bool safe) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Error'),
        content: Text(message),
        actions: <Widget>[
          TextButton(
            child: const Text('OK'),
            onPressed: () {
              Navigator.of(context).pop();
            },
          ),
        ],
      ),
    );
  }

  _urlLauncher(String url) async {
    final _url = Uri.parse(url);
    if(!await launchUrl(_url, mode: LaunchMode.externalApplication)){
      throw Exception('Could not launch $_url');
    }
  }

  Future<void> _checkWithVirusTotal(String url) async {
    const apiKey =
        'f89c464dea42f7e36a4d39ff89112ad618deaf66130bbe383b38ca428b683dcd';
    final encodedUrl = base64Url
        .encode(utf8.encode(url))
        .replaceAll('=', ''); // Encode and remove padding final apiUrl =
    final apiUrl = 'https://www.virustotal.com/api/v3/urls/$encodedUrl';

    try {
      final response = await http.get(
        Uri.parse(apiUrl),
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/json',
        },
      );

      if (response.statusCode == 200) {
        final jsonResponse = json.decode(response.body);
        // Tampilkan hasil dari VirusTotal (misalnya dideteksi atau aman)
        final scanResult =
            jsonResponse['data']['attributes']['last_analysis_stats'];

        bool safe = true;
        if(scanResult['malicious'] > 0 || scanResult['suspicious'] > 0) {
          safe = false;
        }

        showDialog(
          context: context,
          builder: (_) => AlertDialog(
            title: const Text('VirusTotal Result'),
            titleTextStyle: TextStyle(color: Colors.black, fontWeight: FontWeight.bold, fontSize: 30.0),
            content: Text(safe ? 'Hasil menunjukan $url aman untuk dikunjungi.' : '$url adalah link berbahaya, sebaiknya anda berhati-hati jika tetap ingin mengunjungi halaman tersebut.'),
            contentTextStyle: TextStyle(color: safe ? Colors.black : Colors.red),
            actions: <Widget>[
              if (safe)
                ...[TextButton(
                  child: const Text('Buka link', style: TextStyle(color: Colors.blue),),
                  style: TextButton.styleFrom(backgroundColor: Colors.blue[50]),
                  onPressed: () {
                    _urlLauncher(url);
                  },
                ),
                TextButton(
                  child: const Text('cancel'),
                  onPressed: () {
                    Navigator.of(context).pop();
                  },
                )]
              else
                ...[
                  TextButton(
                    child: const Text('Tetap Buka Link'),
                    onPressed: () {
                      Navigator.of(context).pop();
                    },
                  ),
                  TextButton(
                    child: const Text('OK'),
                    onPressed: () {
                      Navigator.of(context).pop();
                    },
                  ),
                ]
            ],
          ),
        );
      } else {
        _showErrorDialog('Error: Unable to scan the URL with VirusTotal.', false);
      }
    } catch (e) {
      _showErrorDialog('Error: $e', true);
    }

    @override
    void dispose() {
      controller?.dispose();
      super.dispose();
    }
  }
}
