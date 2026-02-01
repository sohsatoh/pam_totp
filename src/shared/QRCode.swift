import Foundation

/// QR Code generator for terminal display using UTF-8 block characters
public struct QRCode {
    
    /// Generate QR code data matrix
    public static func generate(from string: String) -> [[Bool]]? {
        // Use Core Image for QR generation
        guard let data = string.data(using: .utf8) else { return nil }
        
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(data, forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel") // Medium error correction
        
        guard let ciImage = filter.outputImage else { return nil }
        
        // Scale up for better rendering
        let scale = CGAffineTransform(scaleX: 1, y: 1)
        let scaledImage = ciImage.transformed(by: scale)
        
        let context = CIContext()
        guard let cgImage = context.createCGImage(scaledImage, from: scaledImage.extent) else { return nil }
        
        let width = cgImage.width
        let height = cgImage.height
        
        // Create bitmap context to read pixels
        guard let dataProvider = cgImage.dataProvider,
              let pixelData = dataProvider.data else { return nil }
        
        let data2 = CFDataGetBytePtr(pixelData)!
        let bytesPerPixel = cgImage.bitsPerPixel / 8
        let bytesPerRow = cgImage.bytesPerRow
        
        var matrix: [[Bool]] = []
        for y in 0..<height {
            var row: [Bool] = []
            for x in 0..<width {
                let offset = y * bytesPerRow + x * bytesPerPixel
                // Check if pixel is dark (QR code black module)
                let r = data2[offset]
                let isDark = r < 128
                row.append(isDark)
            }
            matrix.append(row)
        }
        
        return matrix
    }
    
    /// Render QR code to terminal string using Unicode block characters
    public static func renderToTerminal(from string: String, invert: Bool = false) -> String? {
        guard let matrix = generate(from: string) else { return nil }
        return renderMatrix(matrix, invert: invert)
    }
    
    /// Render matrix to terminal string
    public static func renderMatrix(_ matrix: [[Bool]], invert: Bool = false) -> String {
        let height = matrix.count
        guard height > 0 else { return "" }
        let width = matrix[0].count
        
        var result = ""
        
        // Add quiet zone (border)
        let quietZone = 2
        let fullWidth = width + quietZone * 2
        
        // Use half-block characters for 2:1 aspect ratio
        // ▀ (upper half), ▄ (lower half), █ (full), ' ' (empty)
        let topHalf = "▀"
        let bottomHalf = "▄"
        let fullBlock = "█"
        let emptyBlock = " "
        
        // Top quiet zone
        for _ in 0..<quietZone/2 {
            result += String(repeating: invert ? fullBlock : emptyBlock, count: fullWidth) + "\n"
        }
        
        // Process two rows at a time
        var y = 0
        while y < height {
            // Left quiet zone
            result += String(repeating: invert ? fullBlock : emptyBlock, count: quietZone)
            
            for x in 0..<width {
                let topDark = matrix[y][x]
                let bottomDark = (y + 1 < height) ? matrix[y + 1][x] : false
                
                let top = invert ? !topDark : topDark
                let bottom = invert ? !bottomDark : bottomDark
                
                if top && bottom {
                    result += fullBlock
                } else if top && !bottom {
                    result += topHalf
                } else if !top && bottom {
                    result += bottomHalf
                } else {
                    result += emptyBlock
                }
            }
            
            // Right quiet zone
            result += String(repeating: invert ? fullBlock : emptyBlock, count: quietZone)
            result += "\n"
            
            y += 2
        }
        
        // Bottom quiet zone
        for _ in 0..<quietZone/2 {
            result += String(repeating: invert ? fullBlock : emptyBlock, count: fullWidth) + "\n"
        }
        
        return result
    }
}

#if canImport(CoreImage)
import CoreImage
#endif
