/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.facebook.presto.orc.writer;

import com.facebook.presto.orc.checkpoint.BooleanStreamCheckpoint;
import com.facebook.presto.orc.checkpoint.LongStreamCheckpoint;
import com.facebook.presto.orc.metadata.ColumnEncoding;
import com.facebook.presto.orc.metadata.CompressionKind;
import com.facebook.presto.orc.metadata.MetadataWriter;
import com.facebook.presto.orc.metadata.RowGroupIndex;
import com.facebook.presto.orc.metadata.Stream;
import com.facebook.presto.orc.metadata.Stream.StreamKind;
import com.facebook.presto.orc.metadata.statistics.ColumnStatistics;
import com.facebook.presto.orc.stream.LongOutputStream;
import com.facebook.presto.orc.stream.PresentOutputStream;
import com.facebook.presto.spi.block.Block;
import com.facebook.presto.spi.block.ColumnarMap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import io.airlift.slice.SliceOutput;
import org.openjdk.jol.info.ClassLayout;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.facebook.presto.orc.metadata.ColumnEncoding.ColumnEncodingKind.DIRECT;
import static com.facebook.presto.orc.metadata.ColumnEncoding.ColumnEncodingKind.DIRECT_V2;
import static com.facebook.presto.orc.metadata.CompressionKind.NONE;
import static com.facebook.presto.orc.stream.LongOutputStream.createLengthOutputStream;
import static com.facebook.presto.spi.block.ColumnarMap.toColumnarMap;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;
import static java.util.Objects.requireNonNull;

public class MapColumnWriter
        implements ColumnWriter
{
    private static final int INSTANCE_SIZE = ClassLayout.parseClass(MapColumnWriter.class).instanceSize();
    private final int column;
    private final boolean compressed;
    private final ColumnEncoding columnEncoding;
    private final LongOutputStream lengthStream;
    private final PresentOutputStream presentStream;
    private final ColumnWriter keyWriter;
    private final ColumnWriter valueWriter;

    private final List<ColumnStatistics> rowGroupColumnStatistics = new ArrayList<>();

    private int nonNullValueCount;

    private boolean closed;

    public MapColumnWriter(int column, CompressionKind compression, int bufferSize, boolean isDwrf, ColumnWriter keyWriter, ColumnWriter valueWriter)
    {
        checkArgument(column >= 0, "column is negative");
        this.column = column;
        this.compressed = requireNonNull(compression, "compression is null") != NONE;
        this.columnEncoding = new ColumnEncoding(isDwrf ? DIRECT : DIRECT_V2, 0);
        this.keyWriter = requireNonNull(keyWriter, "keyWriter is null");
        this.valueWriter = requireNonNull(valueWriter, "valueWriter is null");
        this.lengthStream = createLengthOutputStream(compression, bufferSize, isDwrf);
        this.presentStream = new PresentOutputStream(compression, bufferSize);
    }

    @Override
    public List<ColumnWriter> getNestedColumnWriters()
    {
        return ImmutableList.<ColumnWriter>builder()
                .add(keyWriter)
                .addAll(keyWriter.getNestedColumnWriters())
                .add(valueWriter)
                .addAll(valueWriter.getNestedColumnWriters())
                .build();
    }

    @Override
    public Map<Integer, ColumnEncoding> getColumnEncodings()
    {
        ImmutableMap.Builder<Integer, ColumnEncoding> encodings = ImmutableMap.builder();
        encodings.put(column, columnEncoding);
        encodings.putAll(keyWriter.getColumnEncodings());
        encodings.putAll(valueWriter.getColumnEncodings());
        return encodings.build();
    }

    @Override
    public void beginRowGroup()
    {
        lengthStream.recordCheckpoint();
        presentStream.recordCheckpoint();

        keyWriter.beginRowGroup();
        valueWriter.beginRowGroup();
    }

    @Override
    public void writeBlock(Block block)
    {
        checkState(!closed);
        checkArgument(block.getPositionCount() > 0, "Block is empty");

        ColumnarMap columnarMap = toColumnarMap(block);
        writeColumnarMap(columnarMap);
    }

    private void writeColumnarMap(ColumnarMap columnarMap)
    {
        // write nulls and lengths
        for (int position = 0; position < columnarMap.getPositionCount(); position++) {
            boolean present = !columnarMap.isNull(position);
            presentStream.writeBoolean(present);
            if (present) {
                nonNullValueCount++;
                lengthStream.writeLong(columnarMap.getEntryCount(position));
            }
        }

        // write keys and value
        Block keysBlock = columnarMap.getKeysBlock();
        if (keysBlock.getPositionCount() > 0) {
            keyWriter.writeBlock(keysBlock);
            valueWriter.writeBlock(columnarMap.getValuesBlock());
        }
    }

    @Override
    public Map<Integer, ColumnStatistics> finishRowGroup()
    {
        checkState(!closed);

        ColumnStatistics statistics = new ColumnStatistics((long) nonNullValueCount, null, null, null, null, null, null, null);
        rowGroupColumnStatistics.add(statistics);
        nonNullValueCount = 0;

        ImmutableMap.Builder<Integer, ColumnStatistics> columnStatistics = ImmutableMap.builder();
        columnStatistics.put(column, statistics);
        columnStatistics.putAll(keyWriter.finishRowGroup());
        columnStatistics.putAll(valueWriter.finishRowGroup());
        return columnStatistics.build();
    }

    @Override
    public void close()
    {
        closed = true;
        keyWriter.close();
        valueWriter.close();
        lengthStream.close();
        presentStream.close();
    }

    @Override
    public Map<Integer, ColumnStatistics> getColumnStripeStatistics()
    {
        checkState(closed);
        ImmutableMap.Builder<Integer, ColumnStatistics> columnStatistics = ImmutableMap.builder();
        columnStatistics.put(column, ColumnStatistics.mergeColumnStatistics(rowGroupColumnStatistics));
        columnStatistics.putAll(keyWriter.getColumnStripeStatistics());
        columnStatistics.putAll(valueWriter.getColumnStripeStatistics());
        return columnStatistics.build();
    }

    @Override
    public List<Stream> writeIndexStreams(SliceOutput outputStream, MetadataWriter metadataWriter)
            throws IOException
    {
        checkState(closed);

        ImmutableList.Builder<RowGroupIndex> rowGroupIndexes = ImmutableList.builder();

        List<LongStreamCheckpoint> lengthCheckpoints = lengthStream.getCheckpoints();
        Optional<List<BooleanStreamCheckpoint>> presentCheckpoints = presentStream.getCheckpoints();
        for (int i = 0; i < rowGroupColumnStatistics.size(); i++) {
            int groupId = i;
            ColumnStatistics columnStatistics = rowGroupColumnStatistics.get(groupId);
            LongStreamCheckpoint lengthCheckpoint = lengthCheckpoints.get(groupId);
            Optional<BooleanStreamCheckpoint> presentCheckpoint = presentCheckpoints.map(checkpoints -> checkpoints.get(groupId));
            List<Integer> positions = createArrayColumnPositionList(compressed, lengthCheckpoint, presentCheckpoint);
            rowGroupIndexes.add(new RowGroupIndex(positions, columnStatistics));
        }

        int length = metadataWriter.writeRowIndexes(outputStream, rowGroupIndexes.build());
        Stream stream = new Stream(column, StreamKind.ROW_INDEX, length, false);

        ImmutableList.Builder<Stream> indexStreams = ImmutableList.builder();
        indexStreams.add(stream);
        indexStreams.addAll(keyWriter.writeIndexStreams(outputStream, metadataWriter));
        indexStreams.addAll(valueWriter.writeIndexStreams(outputStream, metadataWriter));
        return indexStreams.build();
    }

    private static List<Integer> createArrayColumnPositionList(
            boolean compressed,
            LongStreamCheckpoint lengthCheckpoint,
            Optional<BooleanStreamCheckpoint> presentCheckpoint)
    {
        ImmutableList.Builder<Integer> positionList = ImmutableList.builder();
        presentCheckpoint.ifPresent(booleanStreamCheckpoint -> positionList.addAll(booleanStreamCheckpoint.toPositionList(compressed)));
        positionList.addAll(lengthCheckpoint.toPositionList(compressed));
        return positionList.build();
    }

    @Override
    public List<Stream> writeDataStreams(SliceOutput outputStream)
            throws IOException
    {
        checkState(closed);

        ImmutableList.Builder<Stream> dataStreams = ImmutableList.builder();
        presentStream.writeDataStreams(column, outputStream).ifPresent(dataStreams::add);
        lengthStream.writeDataStreams(column, outputStream).ifPresent(dataStreams::add);
        dataStreams.addAll(keyWriter.writeDataStreams(outputStream));
        dataStreams.addAll(valueWriter.writeDataStreams(outputStream));
        return dataStreams.build();
    }

    @Override
    public long getBufferedBytes()
    {
        return lengthStream.getBufferedBytes() + presentStream.getBufferedBytes() + keyWriter.getBufferedBytes() + valueWriter.getBufferedBytes();
    }

    @Override
    public long getRetainedBytes()
    {
        // NOTE: we do not include stats because they should be small and it would be annoying to calculate the size
        return INSTANCE_SIZE + lengthStream.getRetainedBytes() + presentStream.getRetainedBytes() + keyWriter.getRetainedBytes() + valueWriter.getRetainedBytes();
    }

    @Override
    public void reset()
    {
        closed = false;
        lengthStream.reset();
        presentStream.reset();
        keyWriter.reset();
        valueWriter.reset();
        rowGroupColumnStatistics.clear();
        nonNullValueCount = 0;
    }
}
