// Function to update reports list without page reload
async function updateReportsList() {
    try {
        const response = await fetch(`${backendBase}/api/list_gallery_files`);
        if (!response.ok) {
            throw new Error('Failed to fetch reports');
        }
        const data = await response.json();
        
        // Get the reports container
        const reportsContainer = document.querySelector('#web-scan-reports');
        if (!reportsContainer) return;

        // Filter and sort reports
        const reports = data.files.filter(file => file.source === 'zap_report')
                                .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        // Update the reports display
        let reportsHtml = `<h2 class="text-2xl font-bold mb-4">Web Application Scan Reports</h2>`;
        
        if (reports.length === 0) {
            reportsHtml += `<p class="text-gray-600">No reports generated yet.</p>`;
        } else {
            reportsHtml += `<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">`;
            reports.forEach(report => {
                reportsHtml += `
                    <div class="bg-white shadow rounded-lg p-4">
                        <h3 class="text-lg font-semibold mb-2">${
                            report.fileName.includes('Dark_Custom_Report') ? 'Dark Custom Report' :
                            report.fileName.includes('Light_Custom_Report') ? 'Light Custom Report' :
                            report.fileName.includes('ZAP_Native_Report') ? 'ZAP Native Report' :
                            report.fileName.includes('CyberGuard_6Risk_Report') ? 'CyberGuard 6-Risk Matrix Report' :
                            report.fileName
                        }: ${report.fileName.split('_').pop().split('.')[0]}</h3>
                        <div class="flex justify-between items-center mt-2">
                            <a href="${report.fileUrl}" target="_blank" 
                               class="text-blue-600 hover:text-blue-800">View</a>
                            <button onclick="deleteReport('${report.fileName}')" 
                                    class="text-red-600 hover:text-red-800">Delete</button>
                        </div>
                    </div>`;
            });
            reportsHtml += `</div>`;
        }
        
        // Update only the reports section
        const reportsSection = document.querySelector('#reports-section');
        if (reportsSection) {
            reportsSection.innerHTML = reportsHtml;
        }
    } catch (error) {
        console.error('Error updating reports list:', error);
        // Show error toast if needed
        showToast('Failed to update reports list', 'error');
    }
}
