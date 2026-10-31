import KeyflapApproverCore
import SwiftUI

/// Everything decided (or seen ending) on this iPhone, newest first, grouped by day.
/// Kept only on this phone.
struct HistoryView: View {
    @EnvironmentObject private var model: AppModel
    @State private var confirmClear = false

    private struct Day: Identifiable {
        let day: Date
        let entries: [HistoryEntry]
        var id: Date { day }
    }

    private var days: [Day] {
        let cal = Calendar.current
        let groups = Dictionary(grouping: model.history) { cal.startOfDay(for: $0.at) }
        return groups.keys.sorted(by: >).map { d in
            Day(day: d, entries: (groups[d] ?? []).sorted { $0.at > $1.at })
        }
    }

    var body: some View {
        List {
            if model.history.isEmpty {
                ContentUnavailableView(
                    "No activity yet",
                    systemImage: "clock",
                    description: Text("Requests you approve or deny on this iPhone appear here.")
                )
                .listRowBackground(Color.clear)
            }
            ForEach(days) { group in
                Section(group.day.formatted(date: .complete, time: .omitted)) {
                    ForEach(group.entries) { e in
                        VStack(alignment: .leading, spacing: 6) {
                            HistoryRow(entry: e)
                            if let site = e.site {
                                Text(Formatting.clean(site))
                                    .font(.caption2.monospaced())
                                    .foregroundStyle(.secondary)
                                    .padding(.leading, 40)
                            }
                        }
                        .padding(.vertical, 2)
                    }
                }
            }
        }
        .navigationTitle("Activity")
        .toolbar {
            if !model.history.isEmpty {
                Button("Clear", role: .destructive) { confirmClear = true }
            }
        }
        .confirmationDialog("Clear the activity list on this iPhone?", isPresented: $confirmClear, titleVisibility: .visible) {
            Button("Clear activity", role: .destructive) { model.clearHistory() }
        } message: {
            Text("The broker's own audit log is not affected.")
        }
    }
}
